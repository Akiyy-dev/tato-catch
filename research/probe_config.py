"""Pure configuration helpers; never start or attach a process."""
import hashlib
import json
from pathlib import Path

EXPECTED_EXE_SHA256 = "76c9c41b7dfac2861f3d30aea53e7a6261b136c610acddd87097dae8f1a6de58"


def validate_target(value, expected_sha256=EXPECTED_EXE_SHA256):
    target = Path(value).resolve(strict=True)
    if target.name.lower() != "tatotalk.exe" or not target.is_file():
        raise ValueError("Target must be the supported Tatotalk.exe file")
    if hashlib.sha256(target.read_bytes()).hexdigest() != expected_sha256:
        raise ValueError("Target executable changed; refusing to attach")
    return target


def bind_probe(source, target):
    placeholder = "/*TARGET_EXE*/null"
    if source.count(placeholder) != 1:
        raise ValueError("Probe must contain exactly one target configuration placeholder")
    return source.replace(placeholder, json.dumps(str(target), ensure_ascii=True), 1)
