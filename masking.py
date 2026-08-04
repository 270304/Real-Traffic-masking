"""
masking.py
----------
Two distinct concepts, kept deliberately separate:

1. DISPLAY MASKING (irreversible) — what everyone without unmask rights sees.
   For plate text: partial redaction, e.g. "MH12AB1234" -> "MH12**1234".
   For images/video: faces and plates are detected and blurred out-of-place;
   the blurred file is a genuinely different (lossy, irreversible) artifact,
   not a "hidden" original.

2. PROTECTED STORAGE (reversible, key-gated) — the real data, encrypted with
   Fernet symmetric encryption. Only unlocked via decrypt_protected /
   decrypt_file, and ONLY after AccessControl has approved the request.

Key management (this file, DEMO ONLY):
- The Fernet key is read from the MASKING_FERNET_KEY environment variable.
- If it's not set, a key is generated for the process and a warning is
  logged — this means data encrypted in one run is NOT decryptable in a
  later run. That's fine for a demo, wrong for production.
- In production: keep the key in a secrets manager (Vault, AWS/GCP KMS,
  etc.), never in code or a plain env var on disk. Rotate periodically and
  re-encrypt protected payloads on rotation.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

# --- Key management --------------------------------------------------------

_env_key = os.environ.get("MASKING_FERNET_KEY")
if _env_key:
    _DEMO_KEY = _env_key.encode("utf-8")
else:
    _DEMO_KEY = Fernet.generate_key()
    logger.warning(
        "MASKING_FERNET_KEY not set — generated an ephemeral key for this "
        "process. Data encrypted now will NOT be decryptable after restart. "
        "Set MASKING_FERNET_KEY (from a secrets manager) in production."
    )

_fernet = Fernet(_DEMO_KEY)


# --- Protected storage: small in-memory payloads (plate text, etc.) --------

def encrypt_protected(raw_value: str) -> bytes:
    """Encrypt a small text payload before storing it in CaptureRecord.protected_payload."""
    return _fernet.encrypt(raw_value.encode("utf-8"))


def decrypt_protected(payload: bytes) -> str:
    """
    Decrypt a small protected payload. Must ONLY ever be called from inside
    AccessControl, after authorization has been confirmed.
    """
    try:
        return _fernet.decrypt(payload).decode("utf-8")
    except InvalidToken as e:
        raise ValueError("Decryption failed — wrong key or corrupted payload.") from e


# --- Protected storage: large file-backed payloads (video) -----------------

def encrypt_file(input_path: str | Path, output_path: str | Path) -> None:
    """
    Encrypt a file (e.g. a raw video clip) and write the ciphertext to
    `output_path`. The caller is responsible for deleting the plaintext
    original once this returns successfully.

    Note: Fernet encrypts the whole payload as one token, so this loads the
    file into memory. Fine for demo-scale clips; for large video in
    production, switch to chunked AES-GCM streaming encryption instead.
    """
    input_path, output_path = Path(input_path), Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    plaintext = input_path.read_bytes()
    ciphertext = _fernet.encrypt(plaintext)
    output_path.write_bytes(ciphertext)
    # Restrict to owner read/write only — this holds the encrypted video.
    os.chmod(output_path, 0o600)


def decrypt_file(input_path: str | Path, output_path: str | Path) -> None:
    """
    Decrypt a protected file to `output_path`. Must ONLY ever be called from
    inside AccessControl, after authorization has been confirmed. The
    decrypted output should be treated as sensitive and cleaned up by the
    caller (see access_control.AccessControl.revoke_temp_access).
    """
    input_path, output_path = Path(input_path), Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        ciphertext = input_path.read_bytes()
        plaintext = _fernet.decrypt(ciphertext)
    except InvalidToken as e:
        raise ValueError("Decryption failed — wrong key or corrupted file.") from e

    output_path.write_bytes(plaintext)
    os.chmod(output_path, 0o600)


# --- Display masking: plate text (irreversible, safe to show to anyone) ----

_PLATE_PATTERN = re.compile(r"^([A-Z]{2}\d{2})([A-Z]{1,2})(\d{4})$")


def mask_plate(plate_text: str) -> str:
    """
    Irreversibly mask a license plate for display.
    Example: 'MH12AB1234' -> 'MH12**1234' (state+district visible, identity hidden)
    Falls back to full masking if the format isn't recognized.
    """
    plate_text = plate_text.upper().replace(" ", "")
    match = _PLATE_PATTERN.match(plate_text)
    if match:
        state_district, _letters, last4 = match.groups()
        return f"{state_district}**{last4}"
    return "*" * len(plate_text)


def mask_face_reference(face_image_path: str) -> str:
    """
    Returns a reference string pointing to a blurred version of a face image.
    See `blur_image_file` for the real pixel-level implementation used on
    single frames/images.
    """
    return f"blurred::{face_image_path}"


# --- Display masking: images and video (real, irreversible pixel blurring) -

# Haar cascades ship with opencv-python(-headless); no external download.
_FACE_CASCADE_PATH = None
_PLATE_CASCADE_PATH = None


def _get_cascades():
    """Lazily load OpenCV cascades so importing this module doesn't require
    cv2 unless video/image masking is actually used."""
    global _FACE_CASCADE_PATH, _PLATE_CASCADE_PATH
    import cv2  # local import: keep cv2 optional for callers who only need text masking

    if _FACE_CASCADE_PATH is None:
        _FACE_CASCADE_PATH = str(Path(cv2.data.haarcascades) / "haarcascade_frontalface_alt2.xml")
        _PLATE_CASCADE_PATH = str(Path(cv2.data.haarcascades) / "haarcascade_russian_plate_number.xml")

    face_cascade = cv2.CascadeClassifier(_FACE_CASCADE_PATH)
    plate_cascade = cv2.CascadeClassifier(_PLATE_CASCADE_PATH)
    return cv2, face_cascade, plate_cascade


def _blur_regions(cv2, frame, cascade, min_size=(40, 40)):
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    regions = cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=min_size)
    for (x, y, w, h) in regions:
        roi = frame[y:y + h, x:x + w]
        # Heavy Gaussian blur — irreversible, not just "hidden".
        k = max(31, (min(w, h) // 2) | 1)  # odd kernel size, scales with region
        frame[y:y + h, x:x + w] = cv2.GaussianBlur(roi, (k, k), 0)
    return len(regions)


def blur_image_file(input_path: str | Path, output_path: str | Path) -> int:
    """Blur detected faces and plates in a single image. Returns detection count."""
    cv2, face_cascade, plate_cascade = _get_cascades()
    frame = cv2.imread(str(input_path))
    if frame is None:
        raise ValueError(f"Could not read image: {input_path}")

    count = _blur_regions(cv2, frame, face_cascade)
    count += _blur_regions(cv2, frame, plate_cascade, min_size=(60, 20))

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    cv2.imwrite(str(output_path), frame)
    return count


def mask_video(input_path: str | Path, output_path: str | Path) -> int:
    """
    Produce a display-safe, irreversibly masked copy of a video: every frame
    is scanned for faces and plate-like regions, which are heavily blurred.

    Returns the total number of regions blurred across all frames (useful
    for logging/QA — e.g. "0 detections" on a clip that obviously has a
    face is a signal something's wrong, not a guarantee of privacy).

    This is a reasonable baseline (Haar cascades, CPU-only, no extra
    downloads). For production-grade footage, swap in a proper detector
    (e.g. the YOLOv8 + ByteTrack pipeline already used elsewhere in this
    project) — the blur step and the RBAC/encryption around it stay the same.
    """
    cv2, face_cascade, plate_cascade = _get_cascades()

    cap = cv2.VideoCapture(str(input_path))
    if not cap.isOpened():
        raise ValueError(f"Could not open video: {input_path}")

    fps = cap.get(cv2.CAP_PROP_FPS) or 25.0
    width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fourcc = cv2.VideoWriter_fourcc(*"mp4v")
    writer = cv2.VideoWriter(str(output_path), fourcc, fps, (width, height))

    total_detections = 0
    try:
        while True:
            ok, frame = cap.read()
            if not ok:
                break
            total_detections += _blur_regions(cv2, frame, face_cascade)
            total_detections += _blur_regions(cv2, frame, plate_cascade, min_size=(60, 20))
            writer.write(frame)
    finally:
        cap.release()
        writer.release()

    logger.info("mask_video: %s -> %s (%d regions blurred)", input_path, output_path, total_detections)
    return total_detections
