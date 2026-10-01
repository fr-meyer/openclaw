"""Reject any source overlay outside the reviewed release-only fixture files."""
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
bindings = json.loads((HERE / "expected-overlay-files.json").read_text())
expected = {x["path"] for x in bindings["files"]}
expected.add("ci/task20-native-owner57/expected-overlay-files.json")
actual = set(Path(sys.argv[1]).read_text().splitlines())
if actual != expected:
    raise SystemExit("source-only overlay path set differs from review")
for row in bindings["files"]:
    path = ROOT / row["path"]
    if path.is_symlink() or not path.is_file() or path.stat().st_size != row["bytes"]:
        raise SystemExit("overlay physical file identity mismatch")
    if hashlib.sha256(path.read_bytes()).hexdigest() != row["sha256"]:
        raise SystemExit("overlay physical file hash mismatch")
print("exact reviewed source-only fixture overlay verified")
