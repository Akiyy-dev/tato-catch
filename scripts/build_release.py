"""Build a deterministic, audited TatoTalk source probe kit without client access."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

from verify import SourceError, audit_entry, collect_sources


VERSION_PATTERN = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?\Z")


def build_archive(root, *, version=None, output_dir=None):
    root = Path(root).resolve()
    files, commit = collect_sources(root)
    if "VERSION" not in files:
        raise SourceError("The source set must include VERSION")
    selected_version = files["VERSION"].decode("utf-8-sig").strip() if version is None else version
    if not isinstance(selected_version, str) or not VERSION_PATTERN.fullmatch(selected_version):
        raise SourceError("Version must be a safe semantic version such as 0.1.0-alpha.1")
    if version is not None:
        # Override only archive contents; the user's working tree remains untouched.
        files["VERSION"] = (selected_version + "\n").encode("utf-8")
        audit_entry("VERSION", files["VERSION"])
    manifest = {
        "name": "tato-catch",
        "version": selected_version,
        "git_commit": commit,
        "files": [{"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                  for name, data in sorted(files.items())],
    }
    contents = dict(files)
    contents["MANIFEST.json"] = (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    destination = Path(output_dir) if output_dir is not None else root / "dist"
    if not destination.is_absolute():
        destination = root / destination
    destination = destination.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    archive_path = destination / f"tato-catch-{selected_version}-source-probe-kit.zip"
    temporary_path = archive_path.with_suffix(".zip.tmp")
    prefix = f"tato-catch-{selected_version}/"
    try:
        # Stored entries avoid compressor-version drift; this small kit contains text only.
        with zipfile.ZipFile(temporary_path, "w", compression=zipfile.ZIP_STORED) as archive:
            for name, data in sorted(contents.items()):
                info = zipfile.ZipInfo(prefix + name, date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                info.compress_type = zipfile.ZIP_STORED
                archive.writestr(info, data)
        temporary_path.replace(archive_path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()
    checksum = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    (destination / "SHA256SUMS").write_bytes(f"{checksum}  {archive_path.name}\n".encode("ascii"))
    return archive_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--version", help="Override VERSION in archive contents only")
    parser.add_argument("--output-dir", type=Path, default=Path("dist"))
    args = parser.parse_args()
    try:
        archive_path = build_archive(args.root, version=args.version, output_dir=args.output_dir)
    except (SourceError, OSError) as error:
        parser.exit(1, f"Build failed: {error}\n")
    print(json.dumps({"archive": str(archive_path), "checksums": str(archive_path.parent / "SHA256SUMS")}, indent=2))


if __name__ == "__main__":
    main()
