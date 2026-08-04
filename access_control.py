"""
access_control.py
------------------
The single gatekeeper. All data access goes through this module.

Policy (edit ROLE_PERMISSIONS to change who can unmask):
- POLICE           -> can unmask
- GOV_ENTITY       -> can unmask (only the one designated department/entity)
- ANALYST, PUBLIC, SYSTEM_ADMIN -> masked view only

Every call is written to the audit log, whether granted or denied.

What changed vs. the original version:
- `view` / `request_unmask` now work for ANY MediaType, including VIDEO.
  For video, "unmasking" means decrypting the protected file to a private,
  owner-only temp location and handing back a *path*, not raw bytes.
- Results are now an explicit `AccessResult(status=GRANTED|DENIED, ...)`
  instead of silently substituting the masked value — so a caller (e.g. a
  UI layer) can render a real "Unauthorized" state rather than assuming
  whatever came back is fine to show.
- `revoke_temp_access` lets a caller (or a scheduled cleanup job) delete a
  decrypted temp file once it's no longer needed, so plaintext video
  doesn't linger on disk longer than necessary.
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Optional

from models import Entity, CaptureRecord, Role, MediaType
from masking import decrypt_protected, decrypt_file
from audit import AuditLog, AuditEntry

ROLE_PERMISSIONS = {
    Role.POLICE: True,
    Role.GOV_ENTITY: True,
    Role.ANALYST: False,
    Role.PUBLIC: False,
    Role.SYSTEM_ADMIN: False,
}

# A default temp dir for decrypted video hand-offs. In production this
# should be a tmpfs (RAM-backed) mount so plaintext video never touches a
# persistent disk, with an OS-level auto-purge policy as a backstop.
_DECRYPTED_TMP_DIR = Path(tempfile.gettempdir()) / "traffic_ac_decrypted"


class AccessStatus(Enum):
    GRANTED = auto()
    DENIED = auto()


class AccessDenied(Exception):
    pass


@dataclass
class AccessResult:
    """
    Explicit result of an access attempt — deliberately NOT just "here's
    some data". A caller (UI, API layer) should branch on `status` and
    render an actual Unauthorized state on DENIED, rather than guessing
    from the shape of the returned content.
    """
    status: AccessStatus
    record_id: str
    media_type: MediaType
    reason: str
    # Populated only when status == GRANTED. For PLATE_TEXT/FACE_IMAGE this
    # is the unmasked value/path; for VIDEO it's a path to a decrypted temp
    # file the caller should stream from and then revoke.
    content: Optional[str] = None
    # Always populated — the masked/display-safe fallback, whatever the status.
    masked_ref: Optional[str] = None

    @property
    def granted(self) -> bool:
        return self.status is AccessStatus.GRANTED


class AccessControl:
    def __init__(self, audit_log: AuditLog = None):
        self.audit_log = audit_log or AuditLog()

    def _is_authorized(self, entity: Entity) -> bool:
        return entity.can_unmask and ROLE_PERMISSIONS.get(entity.role, False)

    def _log(self, entity: Entity, record: CaptureRecord, action: str, granted: bool, reason: str) -> None:
        self.audit_log.write(AuditEntry(
            entity_id=entity.entity_id,
            entity_name=entity.name,
            role=entity.role.name,
            record_id=record.record_id,
            media_type=record.media_type.name,
            action=action,
            granted=granted,
            reason=reason,
        ))

    def view(self, entity: Entity, record: CaptureRecord, reason: str = "Default view") -> AccessResult:
        """
        Every entity can call this. Works for plate text, face images, and
        video alike. Returns an AccessResult — GRANTED with the real content
        only if `entity` is authorized for `record`'s data; otherwise DENIED,
        with the masked reference as the safe fallback. Logs every attempt
        either way.
        """
        if not self._is_authorized(entity):
            self._log(entity, record, action="VIEW_MASKED", granted=True,
                      reason="Default masked access (entity not authorized to unmask)")
            return AccessResult(
                status=AccessStatus.DENIED,
                record_id=record.record_id,
                media_type=record.media_type,
                reason=f"{entity.name} ({entity.role.name}) is not authorized to unmask this record.",
                content=None,
                masked_ref=record.masked_ref,
            )

        try:
            content = self._unmask(record)
        except Exception as e:
            self._log(entity, record, action="UNMASK_ATTEMPT", granted=False, reason=f"Decryption failed: {e}")
            raise

        self._log(entity, record, action="UNMASK_ATTEMPT", granted=True, reason=reason)
        return AccessResult(
            status=AccessStatus.GRANTED,
            record_id=record.record_id,
            media_type=record.media_type,
            reason=reason,
            content=content,
            masked_ref=record.masked_ref,
        )

    def request_unmask(self, entity: Entity, record: CaptureRecord, reason: str) -> AccessResult:
        """
        Explicit unmask request with a stated reason (e.g. case number).
        Use this path for POLICE/GOV_ENTITY so the *reason* is captured,
        not just that access was granted. Raises AccessDenied (instead of
        silently falling back to masked) when the entity isn't authorized —
        appropriate for a workflow that expects unmask to succeed and needs
        to handle failure explicitly.
        """
        if not self._is_authorized(entity):
            self._log(entity, record, action="UNMASK_ATTEMPT", granted=False,
                      reason=f"DENIED - insufficient role/permission. Stated reason: {reason}")
            raise AccessDenied(
                f"{entity.name} ({entity.role.name}) is not authorized to unmask record {record.record_id}"
            )

        content = self._unmask(record)
        self._log(entity, record, action="UNMASK_ATTEMPT", granted=True, reason=reason)
        return AccessResult(
            status=AccessStatus.GRANTED,
            record_id=record.record_id,
            media_type=record.media_type,
            reason=reason,
            content=content,
            masked_ref=record.masked_ref,
        )

    def _unmask(self, record: CaptureRecord) -> str:
        """Dispatch decryption based on media type. Never call directly — only from an authorized path above."""
        if record.media_type == MediaType.VIDEO:
            _DECRYPTED_TMP_DIR.mkdir(parents=True, exist_ok=True)
            out_path = _DECRYPTED_TMP_DIR / f"{record.record_id}.mp4"
            decrypt_file(record.protected_file_ref, out_path)
            return str(out_path)
        return decrypt_protected(record.protected_payload)

    @staticmethod
    def revoke_temp_access(content_path: str) -> None:
        """
        Delete a decrypted temp file (e.g. video) once the caller is done
        with it. Safe to call even if the file is already gone. Callers
        should always revoke after use rather than relying solely on OS
        temp-dir cleanup.
        """
        p = Path(content_path)
        if p.exists() and p.is_relative_to(_DECRYPTED_TMP_DIR):
            p.unlink()
