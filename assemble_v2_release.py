from __future__ import annotations

import base64
import hashlib
from pathlib import Path

PARTS_DIR = Path(__file__).resolve().parent / "release_parts"
OUTPUT = Path(__file__).resolve().parent / "AutoCyber_Traceability_Workbench_v2.0_source.zip"
EXPECTED_SHA256 = "73ac09951150f5751f9385190312815a8cc53366496900218e3d45d874d5abc3"

parts = sorted(PARTS_DIR.glob("v2_source.zip.b64.part*"))
if not parts:
    raise SystemExit("No release parts found.")

encoded = "".join(part.read_text(encoding="ascii").strip() for part in parts)
OUTPUT.write_bytes(base64.b64decode(encoded))
actual = hashlib.sha256(OUTPUT.read_bytes()).hexdigest()
if actual != EXPECTED_SHA256:
    OUTPUT.unlink(missing_ok=True)
    raise SystemExit(f"Checksum mismatch: {actual}")
print(f"Created {OUTPUT.name}\nSHA-256: {actual}")
