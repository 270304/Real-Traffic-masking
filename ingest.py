"""
ingest.py
---------
Turns a raw camera capture into a `CaptureRecord` the rest of the system
can safely reason about: generate the display-safe masked version, encrypt
the original at rest, and never leave the plaintext original lying around.

This is the piece you call when a new video comes in from a camera; it's
kept separate from access_control.py because ingestion (writing) and access
(reading) are different trust boundaries and usually run in different
services in a real deployment.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from models import CaptureRecord, MediaType
from masking import mask_plate, encrypt_protected, mask_video, encrypt_file

# Where encrypted-at-rest originals and masked (public-safe) copies live.
# In production these would be two separate storage backends/buckets with
# different access policies, not just two subfolders.
PROTECTED_STORE_DIR = Path("secure_storage/protected")
MASKED_STORE_DIR = Path("secure_storage/masked")


def ingest_plate_capture(camera_id: str, plate_text: str, location: Optional[str] = None) -> CaptureRecord:
    """Existing-style ingestion path for a plate-text capture (unchanged behavior)."""
    return CaptureRecord(
        camera_id=camera_id,
        media_type=MediaType.PLATE_TEXT,
        masked_ref=mask_plate(plate_text),
        protected_payload=encrypt_protected(plate_text),
        location=location,
    )


def ingest_video_capture(
    camera_id: str,
    raw_video_path: str | Path,
    location: Optional[str] = None,
    notes: Optional[str] = None,
    delete_original: bool = True,
) -> CaptureRecord:
    """
    Ingest a raw video clip captured by a camera:
      1. Produce a masked (faces/plates blurred) copy — safe for anyone to view.
      2. Encrypt the original clip at rest.
      3. Delete the plaintext original (default) so it doesn't sit unprotected
         on disk once step 2 has succeeded.

    Returns a CaptureRecord referencing the masked copy and the encrypted
    original. The encrypted original can only ever be decrypted through
    AccessControl, by an authorized entity.
    """
    raw_video_path = Path(raw_video_path)
    if not raw_video_path.exists():
        raise FileNotFoundError(f"No such video file: {raw_video_path}")

    record_id_hint = raw_video_path.stem
    masked_path = MASKED_STORE_DIR / f"{record_id_hint}_masked.mp4"
    protected_path = PROTECTED_STORE_DIR / f"{record_id_hint}.enc"

    # 1. Masked, display-safe copy (real pixel blurring, irreversible).
    mask_video(raw_video_path, masked_path)

    # 2. Encrypt the original at rest.
    encrypt_file(raw_video_path, protected_path)

    # 3. Don't leave the plaintext original lying around once it's encrypted.
    if delete_original:
        raw_video_path.unlink()

    return CaptureRecord(
        camera_id=camera_id,
        media_type=MediaType.VIDEO,
        masked_ref=str(masked_path),
        protected_file_ref=str(protected_path),
        location=location,
        notes=notes,
    )
