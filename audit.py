"""
audit.py
--------
Append-only audit trail. Every access attempt (granted or denied) is logged
with who, what, when, and why. This is the piece regulators actually check
under GDPR Art. 5(2) accountability / DPDPA's reasonable-security-safeguards
requirement — access control without an audit trail is hard to defend.

In production: write to an append-only store (e.g. a write-once S3 bucket,
or a database table with no UPDATE/DELETE grants for app roles), not a
plain local file.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class AuditEntry:
    entity_id: str
    entity_name: str
    role: str
    record_id: str
    media_type: str       # "PLATE_TEXT" | "FACE_IMAGE" | "VIDEO"
    action: str            # "VIEW_MASKED" | "UNMASK_ATTEMPT"
    granted: bool
    reason: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_json(self) -> str:
        return json.dumps({
            "entity_id": self.entity_id,
            "entity_name": self.entity_name,
            "role": self.role,
            "record_id": self.record_id,
            "media_type": self.media_type,
            "action": self.action,
            "granted": self.granted,
            "reason": self.reason,
            "timestamp": self.timestamp.isoformat(),
        })


class AuditLog:
    """
    Append-only, thread-safe (within one process) audit log backed by a
    JSON-lines file. `write` is safe to call concurrently from multiple
    threads; it is NOT safe against concurrent *processes* writing to the
    same file (use a real database with row-level integrity in production).
    """

    def __init__(self, path: str | Path = "audit_log.jsonl"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write(self, entry: AuditEntry) -> None:
        line = entry.to_json() + "\n"
        with self._lock:
            with open(self.path, "a") as f:
                f.write(line)

    def read_all(self) -> list[dict]:
        try:
            with open(self.path, "r") as f:
                return [json.loads(line) for line in f if line.strip()]
        except FileNotFoundError:
            return []

    def read_for_record(self, record_id: str) -> list[dict]:
        """Convenience filter: full access history for one capture record."""
        return [e for e in self.read_all() if e.get("record_id") == record_id]

    def read_denied(self, entity_id: Optional[str] = None) -> list[dict]:
        """Convenience filter: every denied/unauthorized attempt (optionally by entity)."""
        entries = [e for e in self.read_all() if not e.get("granted", True)]
        if entity_id:
            entries = [e for e in entries if e.get("entity_id") == entity_id]
        return entries
