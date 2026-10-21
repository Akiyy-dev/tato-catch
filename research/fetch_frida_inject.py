"""Download the pinned official Frida CLI archive; no system install."""
import concurrent.futures
import hashlib
import pathlib
import urllib.request

URL = "https://github.com/frida/frida/releases/download/17.24.3/frida-inject-17.24.3-windows-x86_64.exe.xz"
EXPECTED = "20e6f32ae69fa68d44fbdfcdf49c44219350e60447082b3389a29ec61a6dd996"
ROOT = pathlib.Path(__file__).resolve().parent / "tools"
DEST = ROOT / "frida-inject-17.24.3-windows-x86_64.exe.xz"
ROOT.mkdir(exist_ok=True)

if DEST.exists() and hashlib.sha256(DEST.read_bytes()).hexdigest() == EXPECTED:
    print("verified_existing_archive", flush=True)
    raise SystemExit(0)

request = urllib.request.Request(URL, headers={"Range": "bytes=0-0", "User-Agent": "Codex-static-analysis"})
with urllib.request.urlopen(request, timeout=25) as response:
    if response.status != 206:
        raise RuntimeError(f"Range request not honored: HTTP {response.status}")
    total = int(response.headers["Content-Range"].split("/")[-1])
    asset_url = response.geturl()
print(f"archive_bytes={total}", flush=True)

size = 4 * 1024 * 1024
ranges = [(start, min(total - 1, start + size - 1)) for start in range(0, total, size)]

def fetch(bounds):
    start, end = bounds
    query = urllib.request.Request(asset_url, headers={"Range": f"bytes={start}-{end}"})
    with urllib.request.urlopen(query, timeout=45) as response:
        if response.status != 206:
            raise RuntimeError(f"Chunk range not honored: HTTP {response.status}")
        chunk = response.read(end - start + 2)
    if len(chunk) != end - start + 1:
        raise RuntimeError(f"Unexpected chunk size at {start}")
    return start, chunk

output = DEST.with_name(DEST.name + ".range-part")
with output.open("wb") as target:
    target.truncate(total)
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as workers:
        for item in concurrent.futures.as_completed([workers.submit(fetch, bounds) for bounds in ranges]):
            start, chunk = item.result()
            target.seek(start)
            target.write(chunk)
            print(f"received_chunk={start}", flush=True)
actual = hashlib.sha256(output.read_bytes()).hexdigest()
if actual != EXPECTED:
    raise RuntimeError(f"Archive hash mismatch: {actual}")
output.replace(DEST)
print(f"verified_sha256={actual}", flush=True)
