"""Install local analysis dependencies and verify/decompress pinned Frida CLI."""
import argparse
import hashlib
import lzma
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
ARCHIVE_HASH = "20e6f32ae69fa68d44fbdfcdf49c44219350e60447082b3389a29ec61a6dd996"
EXE_HASH = "e2fac3a19b7ad0f9e00e81f3bf10d1090c1471a9b6fb22efbffa21e3f29ee60e"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-only", action="store_true", help="Check existing tools without network or writes")
    args = parser.parse_args()
    if os.name != "nt" or sys.maxsize <= 2**32:
        raise SystemExit("The live probe tool requires Windows x64")
    if sys.version_info < (3, 12):
        raise SystemExit("Python 3.12+ is required")
    tools = ROOT / "research/tools"
    helper = tools / "frida-inject-17.24.3-windows-x86_64.exe"
    if not args.check_only:
        subprocess.run([sys.executable, "-m", "pip", "install", "--disable-pip-version-check",
                        "--target", str(tools / "static-python"), "-r", str(ROOT / "requirements-analysis.txt")], check=True)
        if not helper.is_file() or digest(helper) != EXE_HASH:
            subprocess.run([sys.executable, str(ROOT / "research/fetch_frida_inject.py")], check=True)
            archive = helper.with_suffix(".exe.xz")
            if digest(archive) != ARCHIVE_HASH:
                raise SystemExit("Frida archive hash mismatch")
            temporary = helper.with_name(helper.name + ".unpack-part")
            with lzma.open(archive, "rb") as source, temporary.open("wb") as target:
                while block := source.read(1024 * 1024):
                    target.write(block)
            if digest(temporary) != EXE_HASH:
                raise SystemExit("Frida executable hash mismatch")
            temporary.replace(helper)
    if not helper.is_file() or digest(helper) != EXE_HASH:
        raise SystemExit("Frida CLI is missing or does not match the pinned hash")
    subprocess.run([sys.executable, "-B", "-c",
                    "import sys; sys.path.insert(0, sys.argv[1]); import capstone, pefile; "
                    "assert list(capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64).disasm(b'\\xc3', 0)); "
                    "print('Analysis dependencies OK')", str(tools / "static-python")], check=True)
    print("Pinned Frida CLI verified; no client was started or attached")


if __name__ == "__main__":
    main()
