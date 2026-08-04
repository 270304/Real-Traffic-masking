"""
models.py
---------
Core data structures for the traffic-camera access-control system.

Design principle:
- Every capture (face crop / license plate crop / frame / video clip) is
  stored in TWO forms:
    1. `masked_ref`      -> a blurred/pixelated version, safe for anyone to view
    2. protected original -> encrypted at rest, decryptable ONLY through the
                              AccessControl layer, and ONLY for entities
                              explicitly granted `can_unmask`.
- Nobody gets a decrypted value by accident. Access always goes through
  `access_control.AccessControl`, which logs every attempt.

What changed vs. the original version:
- Added `MediaType` so a record can represent plate text, a face image, OR
  a video clip (previously only small in-memory payloads were supported).
- Protected data can now live either in-memory (`protected_payload`, for
  small values like plate text) or on disk (`protected_file_ref`, for large
  binary media like video), never both.
- `__post_init__` validates the record shape so a malformed record can't
  silently exist half-configured.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import uuid


class Role(Enum):
    PUBLIC = auto()        # e.g. researchers, general analytics dashboards
    ANALYST = auto()       # internal staff doing aggregate/statistical work
    GOV_ENTITY = auto()    # the single designated government department
    POLICE = auto()        # law enforcement, full access
    SYSTEM_ADMIN = auto()  # ops/maintenance — access to system, NOT to unmask data


class MediaType(Enum):
    PLATE_TEXT = auto()   # short string payload, e.g. "MH12AB1234"
    FACE_IMAGE = auto()   # single image (face crop / frame)
    VIDEO = auto()        # video clip, stored as an encrypted file on disk


@dataclass(frozen=True)
class Entity:
    """A party requesting access to the system (a person, department, or service account)."""
    entity_id: str
    name: str
    role: Role
    # Only entities with can_unmask=True may ever see unmasked (protected) data,
    # and even then only if their Role also permits it (defense in depth).
    can_unmask: bool = False


@dataclass
class CaptureRecord:
    """
    A single traffic-camera capture event (plate, face image, or video).

    Exactly one of `protected_payload` (in-memory, for small values) or
    `protected_file_ref` (a path to an encrypted-at-rest file, for video/
    large media) must be set — never both, never neither. `masked_ref`
    is always populated and is always safe to display.
    """
    record_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    camera_id: str = ""
    media_type: MediaType = MediaType.PLATE_TEXT
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    masked_ref: str = ""  # e.g. "MH12**1234" or a path to a blurred image/video

    # Small payloads (plate text, a single face crop) live in memory, encrypted.
    protected_payload: Optional[bytes] = None
    # Large payloads (video) live on disk, encrypted at rest; this is the path
    # to the *encrypted* file. The plaintext original is never retained.
    protected_file_ref: Optional[str] = None

    location: Optional[str] = None
    notes: Optional[str] = None

    def __post_init__(self):
        has_payload = self.protected_payload is not None
        has_file = self.protected_file_ref is not None

        if has_payload == has_file:
            raise ValueError(
                f"CaptureRecord {self.record_id}: exactly one of "
                "protected_payload / protected_file_ref must be set "
                f"(got payload={has_payload}, file={has_file})."
            )

        if self.media_type == MediaType.VIDEO and not has_file:
            raise ValueError(
                f"CaptureRecord {self.record_id}: VIDEO records must use "
                "protected_file_ref, not an in-memory payload."
            )

        if self.media_type != MediaType.VIDEO and not has_payload:
            raise ValueError(
                f"CaptureRecord {self.record_id}: {self.media_type.name} records "
                "must use protected_payload, not protected_file_ref."
            )

        if not self.masked_ref:
            raise ValueError(f"CaptureRecord {self.record_id}: masked_ref is required.")

    @property
    def is_file_backed(self) -> bool:
        return self.protected_file_ref is not None

    def protected_file_path(self) -> Optional[Path]:
        return Path(self.protected_file_ref) if self.protected_file_ref else None
