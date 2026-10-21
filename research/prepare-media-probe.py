"""Bind media probe to code bytes from the hash-checked public sample."""
import json
import pathlib
import sys
from probe_config import validate_target

root = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(root / "tools/static-python"))
import pefile

sample = validate_target(root / "samples/windows-extracted/Tatotalk.exe")
pe = pefile.PE(str(sample), fast_load=True)
candidates = [{"rva": rva, "bytes": pe.get_data(rva, 32).hex()}
              for rva in [0xdb9f80, 0xdb95a0, 0xe52c40, 0xe52050]]
if any(len(item["bytes"]) != 64 for item in candidates):
    raise SystemExit("Expected four full candidate prologues")
source = (root / "windows-marked-media-probe.template.js").read_text(encoding="utf-8")
needle = "/*EXPECTED_CANDIDATES*/null"
if source.count(needle) != 1:
    raise SystemExit("Template placeholder mismatch")
target = root / "windows-marked-media-probe.js"
target.write_text(source.replace(needle, json.dumps(candidates)), encoding="utf-8")
print(json.dumps({"script": target.name, "candidates": len(candidates),
                  "caption": "TATO-IMG-PROBE", "duration_seconds": 170}))
