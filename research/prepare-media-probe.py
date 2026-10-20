"""Bind the disposable media probe to the previously verified code bytes."""
import json
import pathlib

root = pathlib.Path(__file__).resolve().parent
baseline_path = root / "windows-runtime-inspection.json"
if not baseline_path.is_file():
    baseline_path = root / "fixtures/windows-runtime-inspection.json"
baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
candidates = [{"rva": int(item["rva"], 16), "bytes": item["firstBytes"]}
              for item in baseline["candidates"] if item["matches_on_disk_code"]]
if len(candidates) != 4 or any(len(item["bytes"]) != 64 for item in candidates):
    raise SystemExit("Expected four verified candidate prologues")
source = (root / "windows-marked-media-probe.template.js").read_text(encoding="utf-8")
needle = "/*EXPECTED_CANDIDATES*/null"
if source.count(needle) != 1:
    raise SystemExit("Template placeholder mismatch")
target = root / "windows-marked-media-probe.js"
target.write_text(source.replace(needle, json.dumps(candidates)), encoding="utf-8")
print(json.dumps({"script": str(target), "candidates": len(candidates),
                  "caption": "TATO-IMG-PROBE-20261020", "duration_seconds": 170}))
