"""Verify tracked source files without importing or running research probes.

An extracted release uses its hash-checked MANIFEST.json when .git is absent.
No directory walk, client execution, process attachment, or network is involved.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


MAX_FILE_BYTES = 500_000  # Decimal 0.5 MB; applies to each source file.
ROOT_FILES = {"README.md", "VERSION", ".gitignore", ".gitattributes", "requirements-analysis.txt"}
RESEARCH_EXTENSIONS = {".py", ".ps1", ".js", ".md"}
BLOCKED_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".msi", ".cab", ".apk", ".dex",
    ".whl", ".pyc", ".pyo", ".zip", ".xz", ".gz", ".7z", ".jar",
    ".pem", ".key", ".p12", ".pfx", ".db", ".sqlite", ".sqlite3",
    ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".bin", ".part",
}
BLOCKED_PARTS = {"__pycache__", "node_modules", "tools", "samples"}
RESERVED_WINDOWS_NAMES = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                          *(f"LPT{i}" for i in range(1, 10))}
COMMIT_PATTERN = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")

# Decode separator spellings only; never execute or generally unescape source text.
SEPARATOR_ESCAPE_PATTERN = re.compile(r"\\(?:u00(?:5[cC]|2[fF])|x(?:5[cC]|2[fF]))")
NETWORK_URL_PATTERN = re.compile(r"\b(?:https?|wss?|ftps?|ssh|git|s3)://[^\s<>\"'`]+", re.IGNORECASE)
PRIVATE_PATH_PATTERNS = (
    ("Windows drive path", re.compile(r"(?<![\w])[A-Za-z]:[\\/]")),
    ("UNC network path", re.compile(r"(?<![:\\/\w])(?:\\{2,}|/{2,})[\w.-]+[\\/]+[\w$.-]")),
    ("POSIX home path", re.compile(r"(?<![\w/])(?:/(?:home|Users)/[^\s/\"'<>]+|/(?:root)(?:/|(?=$|[\s\"\'<>`]))|~(?:[A-Za-z0-9_.-]+)?/)")),
)


class SourceError(ValueError):
    """The source set violates the release contract."""


def _audit_privacy(name, text):
    """Reject machine-specific paths without copying their values into diagnostics."""
    normalized = SEPARATOR_ESCAPE_PATTERN.sub(
        lambda match: chr(92) if match.group()[-2:].lower() == "5c" else "/", text)
    normalized = normalized.replace(chr(92) + "/", "/")
    # URLs can contain path-shaped components; local file URLs stay subject to checks.
    normalized = NETWORK_URL_PATTERN.sub("<network-url>", normalized)
    normalized = re.sub(r"\bfile:", " ", normalized, flags=re.IGNORECASE)
    for category, pattern in PRIVATE_PATH_PATTERNS:
        if pattern.search(normalized):
            raise SourceError(f"Privacy violation ({category}) in source: {name!r}")


def audit_entry(name, data, *, is_symlink=False):
    """Pure allowlist/content check; return a safe, unchanged POSIX path."""
    if not isinstance(name, str) or not name or "\\" in name or ":" in name:
        raise SourceError(f"Unsafe source path: {name!r}")
    if any(ord(character) < 32 or ord(character) == 127 for character in name):
        raise SourceError(f"Control character in source path: {name!r}")
    parts = name.split("/")
    if any(part in {"", ".", ".."} or part.endswith((" ", ".")) for part in parts):
        raise SourceError(f"Non-canonical source path: {name!r}")
    for part in parts:
        if part.split(".", 1)[0].upper() in RESERVED_WINDOWS_NAMES:
            raise SourceError(f"Reserved Windows source name: {name!r}")
        if part.lower() in BLOCKED_PARTS or part.lower().startswith(".env"):
            raise SourceError(f"Excluded source path: {name!r}")
        if part.startswith(".") and part not in {".github", ".gitignore", ".gitattributes"}:
            raise SourceError(f"Hidden source path is not allowed: {name!r}")
    if parts[:2] == ["research", "fixtures"]:
        raise SourceError(f"Raw research fixtures are not publishable: {name!r}")
    suffix = Path(parts[-1]).suffix.lower()
    allowed = (
        name in ROOT_FILES
        or (len(parts) >= 2 and parts[0] in {"docs", "scripts", "tests"})
        or (len(parts) >= 3 and parts[:2] == [".github", "workflows"])
        or (len(parts) == 2 and parts[0] == "research" and suffix in RESEARCH_EXTENSIONS)
        or (len(parts) == 3 and parts[:2] == ["research", "ghidra-scripts"] and suffix == ".java")
    )
    if not allowed or suffix in BLOCKED_EXTENSIONS:
        raise SourceError(f"Source is outside the text-only allowlist: {name!r}")
    if is_symlink:
        raise SourceError(f"Symbolic links are not allowed: {name!r}")
    if len(data) > MAX_FILE_BYTES:
        raise SourceError(f"Source exceeds {MAX_FILE_BYTES} bytes: {name!r}")
    if b"\x00" in data:
        raise SourceError(f"Binary source content: {name!r}")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise SourceError(f"Source must be UTF-8 text: {name!r}") from error
    if re.search(br"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----", data):
        raise SourceError(f"Private key content is not allowed: {name!r}")
    _audit_privacy(name, text)
    return name


def _read_source(root, name):
    audit_entry(name, b"")  # Check paths before touching the filesystem.
    candidate = root.joinpath(*name.split("/"))
    current = root
    for part in name.split("/"):
        current = current / part
        junction = getattr(current, "is_junction", lambda: False)
        if current.is_symlink() or junction():
            raise SourceError(f"Linked source path is not allowed: {name!r}")
    try:
        candidate.resolve(strict=True).relative_to(root)
        if not candidate.is_file() or candidate.stat().st_size > MAX_FILE_BYTES:
            raise SourceError(f"Source is missing, non-regular, or too large: {name!r}")
        data = candidate.read_bytes()
    except (OSError, ValueError) as error:
        raise SourceError(f"Cannot read a safe source file: {name!r}: {error}") from error
    audit_entry(name, data)
    return data


def _git(root, *arguments):
    try:
        result = subprocess.run(["git", "-C", str(root), *arguments], capture_output=True,
                                check=False, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SourceError(f"Cannot inspect Git source list: {error}") from error
    if result.returncode:
        raise SourceError("Git source inspection failed: " + result.stderr.decode("utf-8", "replace").strip())
    return result.stdout


def collect_sources(root):
    """Read only cached Git paths, or a release manifest; never scan ignored data."""
    root = Path(root).resolve()
    manifest = None
    if (root / ".git").exists():
        actual_root = Path(_git(root, "rev-parse", "--show-toplevel").decode("utf-8").strip()).resolve()
        if actual_root != root:
            raise SourceError("The requested source root must be the Git worktree root")
        commit = _git(root, "rev-parse", "--verify", "HEAD").decode("ascii").strip().lower()
        paths = []
        for record in _git(root, "ls-files", "--cached", "--stage", "-z").split(b"\x00"):
            if not record:
                continue
            header, raw_path = record.split(b"\t", 1)
            mode, _, stage = header.decode("ascii").split()
            if mode not in {"100644", "100755"} or stage != "0":
                raise SourceError("Git links, submodules, and unmerged entries are not source files")
            paths.append(raw_path.decode("utf-8"))
    else:
        manifest_path = root / "MANIFEST.json"
        try:
            if manifest_path.is_symlink() or manifest_path.stat().st_size > MAX_FILE_BYTES:
                raise SourceError("Release manifest must be a small regular text file")
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if (not isinstance(manifest, dict) or manifest.get("name") != "tato-catch"
                    or not isinstance(manifest["files"], list)):
                raise SourceError("Unsupported release manifest")
            commit = manifest["git_commit"]
            paths = [entry["path"] for entry in manifest["files"]]
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise SourceError("Need a Git worktree or a valid extracted release MANIFEST.json") from error
    if not isinstance(commit, str) or not COMMIT_PATTERN.fullmatch(commit):
        raise SourceError("A full Git commit hash is required")
    if not paths:
        raise SourceError("No source files selected")
    files = {}
    seen = set()
    for name in paths:
        audit_entry(name, b"")
        if name.casefold() in seen:
            raise SourceError(f"Duplicate or case-colliding source path: {name!r}")
        seen.add(name.casefold())
        files[name] = _read_source(root, name)
    if manifest is not None:
        for item in manifest["files"]:
            data = files[item["path"]]
            if item.get("size") != len(data) or item.get("sha256") != hashlib.sha256(data).hexdigest():
                raise SourceError(f"Manifest checksum mismatch: {item['path']!r}")
    return dict(sorted(files.items())), commit


def _check_parser(command, source, name):
    try:
        result = subprocess.run(command, input=source.decode("utf-8-sig"), text=True,
                                encoding="utf-8", capture_output=True, check=False, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SourceError(f"Syntax parser unavailable for {name}: {error}") from error
    if result.returncode:
        raise SourceError(f"Syntax error in {name}: {(result.stderr or result.stdout).strip()}")


def verify_repository(root, *, check_node=True, check_powershell=True):
    files, commit = collect_sources(root)
    summary = {"source_files": len(files), "git_commit": commit, "python": 0,
               "javascript": 0, "json": 0, "powershell": 0,
               "node_skipped": not check_node, "powershell_skipped": not check_powershell}
    node = shutil.which("node") if check_node else None
    powershell = (shutil.which("pwsh") or shutil.which("powershell")) if check_powershell else None
    if check_node and not node:
        raise SourceError("Node.js is required for normal verification; use --no-node only for limited checks")
    for name, data in files.items():
        suffix = Path(name).suffix.lower()
        try:
            if suffix == ".py":
                ast.parse(data.decode("utf-8-sig"), filename=name)
                summary["python"] += 1
            elif suffix == ".json":
                json.loads(data.decode("utf-8-sig"))
                summary["json"] += 1
            elif suffix == ".js" and check_node:
                # vm.Script parses Frida's global `const module` without Node's CommonJS wrapper.
                _check_parser([node, "--eval", "new (require('node:vm').Script)(require('node:fs').readFileSync(0,'utf8'), {filename: process.argv[1]});", name], data, name)
                summary["javascript"] += 1
            elif suffix == ".ps1" and check_powershell:
                if not powershell:
                    raise SourceError("PowerShell is required to parse .ps1 sources; use --no-powershell for limited checks")
                parser = "$t=$null; $e=$null; [System.Management.Automation.Language.Parser]::ParseInput([Console]::In.ReadToEnd(),[ref]$t,[ref]$e) | Out-Null; if ($e.Count) { Write-Error ($e | Out-String); exit 1 }"
                _check_parser([powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", parser], data, name)
                summary["powershell"] += 1
        except (SyntaxError, UnicodeError, json.JSONDecodeError) as error:
            raise SourceError(f"Invalid source syntax in {name}: {error}") from error
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--no-node", action="store_true", help="Skip JavaScript syntax checks (limited verification)")
    parser.add_argument("--no-powershell", action="store_true", help="Skip PowerShell syntax checks (limited verification)")
    args = parser.parse_args()
    try:
        summary = verify_repository(args.root, check_node=not args.no_node,
                                    check_powershell=not args.no_powershell)
    except SourceError as error:
        parser.exit(1, f"Verification failed: {error}\n")
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
