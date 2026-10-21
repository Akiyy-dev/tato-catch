"""Bounded Frida CLI probes; closes stdin for normal detach at completion."""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import threading
import time
import tempfile
from probe_config import bind_probe, validate_target

ROOT = pathlib.Path(__file__).resolve().parent
EXPECTED = "76c9c41b7dfac2861f3d30aea53e7a6261b136c610acddd87097dae8f1a6de58"
parser = argparse.ArgumentParser()
parser.add_argument("--target-exe", required=True, help="Full path to the supported Tatotalk.exe")
parser.add_argument("--pid", required=True, type=int)
parser.add_argument("--script", default="windows-module-probe.js")
parser.add_argument("--seconds", type=int, default=8)
parser.add_argument("--marker", default="TATO_MODULE_PROBE:")
parser.add_argument("--report", default="windows-runtime-inspection.json")
parser.add_argument("--ready-marker", default="")
args = parser.parse_args()
TARGET = validate_target(args.target_exe)
if not 1 <= args.seconds <= 180:
    raise SystemExit("Probe duration must be between 1 and 180 seconds")
probe_script = (ROOT / args.script).resolve()
if probe_script.parent != ROOT or not probe_script.is_file():
    raise SystemExit("Probe script must be a file in this research directory")
report_file = (ROOT / args.report).resolve()
if report_file.parent != ROOT:
    raise SystemExit("Report must remain in this research directory")

kernel = ctypes.WinDLL("kernel32", use_last_error=True)
kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel.OpenProcess.restype = wintypes.HANDLE
kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
kernel.QueryFullProcessImageNameW.restype = wintypes.BOOL
kernel.CloseHandle.argtypes = [wintypes.HANDLE]
handle = kernel.OpenProcess(0x1000, False, args.pid)
if not handle:
    raise ctypes.WinError(ctypes.get_last_error())
try:
    name = ctypes.create_unicode_buffer(32768)
    count = wintypes.DWORD(len(name))
    if not kernel.QueryFullProcessImageNameW(handle, 0, name, ctypes.byref(count)):
        raise ctypes.WinError(ctypes.get_last_error())
finally:
    kernel.CloseHandle(handle)
if os.path.normcase(name.value) != os.path.normcase(str(TARGET)):
    raise SystemExit("PID does not refer to the authorized target")
if hashlib.sha256(TARGET.read_bytes()).hexdigest() != EXPECTED:
    raise SystemExit("Target executable changed; refusing to attach")

tool = ROOT / "tools" / "frida-inject-17.24.3-windows-x86_64.exe"
# Configured scripts contain a private path and exist only in the system temp directory.
with tempfile.TemporaryDirectory(prefix="tato-probe-") as temporary:
    configured_script = pathlib.Path(temporary) / "probe.js"
    configured_script.write_text(bind_probe(probe_script.read_text(encoding="utf-8"), TARGET), encoding="utf-8")
    command = [str(tool), "-p", str(args.pid), "-s", str(configured_script), "-i", "-R", "qjs"]
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, encoding="utf-8", errors="replace", creationflags=subprocess.CREATE_NO_WINDOW)
    lines = []
    reader = None
    if args.ready_marker:
        ready_event = threading.Event()
        finished_event = threading.Event()
        def read_output():
            with report_file.with_suffix(".live.output.txt").open("w", encoding="utf-8") as live:
                for line in process.stdout:
                    lines.append(line)
                    live.write(line)
                    live.flush()
                    if args.ready_marker in line:
                        ready_event.set()
                    if args.marker in line:
                        finished_event.set()
        reader = threading.Thread(target=read_output, daemon=True)
        reader.start()
        if ready_event.wait(timeout=12):
            print("PROBE_READY", flush=True)
            finished_event.wait(timeout=args.seconds)
        else:
            print("PROBE_NOT_READY", flush=True)
    else:
        time.sleep(args.seconds)
    if process.stdin:
        try:
            process.stdin.close()
        except BrokenPipeError:
            pass
        process.stdin = None
    forced_exit = False
    try:
        if reader:
            process.wait(timeout=15)
            reader.join(timeout=2)
            output = "".join(lines)
        else:
            output, _ = process.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        forced_exit = True
        process.terminate()  # Only the helper process created immediately above.
        if reader:
            process.wait(timeout=10)
            reader.join(timeout=2)
            output = "".join(lines)
        else:
            output, _ = process.communicate(timeout=10)
    report_file.with_suffix(".output.txt").write_text(output, encoding="utf-8")
    result = None
    for line in output.splitlines():
        payload = line
        try:
            record = json.loads(line)
            if isinstance(record, dict) and record.get("type") == "log":
                payload = record.get("payload", "")
        except ValueError:
            pass
        if args.marker in payload:
            try:
                result, _ = json.JSONDecoder().raw_decode(payload.split(args.marker, 1)[1])
            except ValueError:
                pass
    if result is None:
        print(output[-5000:])
        raise SystemExit("No runtime module result; inspect helper output")
    sys.path.insert(0, str(ROOT / "tools" / "static-python"))
    import pefile
    if "candidates" in result:
        pe = pefile.PE(str(TARGET), fast_load=True)
        for candidate in result["candidates"]:
            data = pe.get_data(int(candidate["rva"], 16), 32)
            candidate["matches_on_disk_code"] = data.hex() == candidate["firstBytes"]
        result["scope"] = "Module metadata plus executable bytes/instructions only; no message hooks or profile/session/chat reads"
    result["helper_returncode"] = process.returncode
    result["helper_forced_exit"] = forced_exit
    result["executable_sha256"] = EXPECTED
    report_file.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"report": str(report_file), "pid": result.get("pid"),
                      "code_matches": [item["matches_on_disk_code"] for item in result.get("candidates", [])],
                      "events": result.get("counts"), "helper_returncode": process.returncode,
                      "helper_forced_exit": forced_exit}, ensure_ascii=False))
