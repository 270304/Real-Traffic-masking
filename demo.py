"""
demo.py
-------
End-to-end demo:
1. A camera "captures" a plate (text) and a short video clip.
2. Both are stored masked (public-safe) + protected (encrypted at rest).
3. Five different entities try to view each record.
4. Only entities with an authorized role AND can_unmask=True get the real
   content; everyone else gets an explicit "Unauthorized" result.
5. Every attempt is written to the audit log.
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

from models import Entity, Role
from masking import mask_plate, encrypt_protected
from access_control import AccessControl, AccessDenied
from audit import AuditLog
from ingest import ingest_video_capture


def make_demo_clip(path: str, n_frames: int = 15) -> None:
    """Create a tiny synthetic video so this demo runs with no external files."""
    import cv2  # local import: only needed when synthesizing a demo clip
    import numpy as np

    fourcc = cv2.VideoWriter_fourcc(*"mp4v")
    writer = cv2.VideoWriter(path, fourcc, 5.0, (320, 240))
    for i in range(n_frames):
        frame = np.full((240, 320, 3), 40, dtype="uint8")
        cv2.putText(frame, f"frame {i}", (30, 120), cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2)
        writer.write(frame)
    writer.release()


def get_video_input(cli_arg: Optional[str] = None) -> str:
    """
    Decide which raw video clip this run of the demo will ingest.

    Priority:
      1. `--video PATH` passed on the command line.
      2. If running interactively (a real terminal), prompt the user for a
         path and fall back to the synthetic demo clip if they just hit Enter.
      3. Otherwise (non-interactive), fall back to the synthetic demo clip.
    """
    if cli_arg:
        path = Path(cli_arg)
        if not path.exists():
            raise FileNotFoundError(f"No such video file: {path}")
        print(f"Using user-supplied video: {path}")
        return str(path)

    if sys.stdin.isatty():
        user_path = input(
            "Enter a path to a video file to ingest (or press Enter to use a synthetic demo clip): "
        ).strip()
        if user_path:
            path = Path(user_path)
            if not path.exists():
                raise FileNotFoundError(f"No such video file: {path}")
            print(f"Using user-supplied video: {path}")
            return str(path)

    print("No video path supplied — generating a synthetic demo clip instead.")
    make_demo_clip("/tmp/demo_raw_clip.mp4")
    return "/tmp/demo_raw_clip.mp4"


parser = argparse.ArgumentParser(description="Traffic access-control demo")
parser.add_argument(
    "--video",
    dest="video",
    default=None,
    help="Path to a video file to ingest. If omitted, you'll be prompted "
         "(or a synthetic demo clip is generated in non-interactive runs).",
)
args, _unknown = parser.parse_known_args()

# --- 1. Simulate camera captures --------------------------------------------
real_plate = "MH12AB1234"
plate_record = None  # built below via ingest for consistency with the video path

from ingest import ingest_plate_capture
plate_record = ingest_plate_capture(camera_id="CAM-BKC-014", plate_text=real_plate,
                                     location="Bandra-Kurla Complex, Mumbai")

raw_video_path = get_video_input(args.video)
video_record = ingest_video_capture(
    camera_id="CAM-BKC-014",
    raw_video_path=raw_video_path,
    location="Bandra-Kurla Complex, Mumbai",
    notes="User-supplied clip" if args.video else "Demo clip",
)

print(f"Plate masked ref stored: {plate_record.masked_ref}")
print(f"Video masked ref stored: {video_record.masked_ref}")
print(f"Video protected (encrypted) file: {video_record.protected_file_ref}\n")

# --- 2. Define entities ------------------------------------------------------
public_dashboard = Entity(entity_id="e-001", name="Public Analytics Dashboard", role=Role.PUBLIC, can_unmask=False)
internal_analyst = Entity(entity_id="e-002", name="Internal Data Analyst", role=Role.ANALYST, can_unmask=False)
transport_dept = Entity(entity_id="e-003", name="State Transport Department", role=Role.GOV_ENTITY, can_unmask=True)
traffic_police = Entity(entity_id="e-004", name="Traffic Police Unit 7", role=Role.POLICE, can_unmask=True)
random_third_party = Entity(entity_id="e-005", name="Third-Party Analytics Vendor", role=Role.ANALYST, can_unmask=True)
# ^ Note: even though can_unmask=True here, role ANALYST is not in the authorized
#   set, so this entity is STILL denied. Two layers have to agree.

audit = AuditLog(path="/home/claude/work/improved/audit_log.jsonl")
ac = AccessControl(audit_log=audit)

entities = [public_dashboard, internal_analyst, transport_dept, traffic_police, random_third_party]

# --- 3. RBAC over the plate-text record --------------------------------------
print("--- Plate record: access attempts ---")
for entity in entities:
    result = ac.view(entity, plate_record)
    if result.granted:
        print(f"{entity.name:32s} ({entity.role.name:12s}) -> GRANTED: {result.content}")
    else:
        print(f"{entity.name:32s} ({entity.role.name:12s}) -> UNAUTHORIZED (shown: {result.masked_ref})")

# --- 4. RBAC over the video record --------------------------------------------
print("\n--- Video record: access attempts ---")
decrypted_paths = []
for entity in entities:
    result = ac.view(entity, video_record)
    if result.granted:
        print(f"{entity.name:32s} ({entity.role.name:12s}) -> GRANTED: decrypted at {result.content}")
        decrypted_paths.append(result.content)
    else:
        print(f"{entity.name:32s} ({entity.role.name:12s}) -> UNAUTHORIZED (shown: {result.masked_ref})")

# Clean up decrypted temp video once viewing is done — don't let plaintext linger.
for p in decrypted_paths:
    AccessControl.revoke_temp_access(p)
print(f"\nRevoked {len(decrypted_paths)} decrypted temp file(s) after viewing.")

# --- 5. Explicit unmask request with a stated reason --------------------------
print("\nExplicit unmask requests with stated reasons (video record):")
for entity in [traffic_police, public_dashboard]:
    try:
        result = ac.request_unmask(entity, video_record, reason="Investigating hit-and-run case #4471")
        print(f"  {entity.name}: GRANTED -> {result.content}")
        AccessControl.revoke_temp_access(result.content)
    except AccessDenied as e:
        print(f"  {entity.name}: DENIED -> {e}")

# --- 6. Show the audit trail ---------------------------------------------------
print("\n--- Audit log (append-only) ---")
for entry in audit.read_all():
    print(entry)

print("\n--- Denied attempts only (e.g. for a compliance report) ---")
for entry in audit.read_denied():
    print(entry)
