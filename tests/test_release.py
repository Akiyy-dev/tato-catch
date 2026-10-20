"""Safety and reproducibility checks for the source-only release tooling."""
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile


PACKAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE / "scripts"))
try:
    verify = importlib.import_module("verify")
    release = importlib.import_module("build_release")
except ImportError:
    verify = release = None


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(verify, "Source verification module must exist")
        self.assertIsNotNone(release, "Release builder must exist")
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, content):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)

    def manifest(self, files):
        for name, data in files.items():
            self.write(name, data)
        manifest = {
            "name": "tato-catch",
            "version": "0.1.0-alpha.1",
            "git_commit": "a" * 40,
            "files": [
                {"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                for name, data in sorted(files.items())
            ],
        }
        self.write("MANIFEST.json", json.dumps(manifest).encode())

    def sources(self):
        files = {"README.md": b"Source release\n", "VERSION": b"0.1.0-alpha.1\n"}
        for name in ("scripts/verify.py", "scripts/build_release.py"):
            files[name] = (PACKAGE / name).read_bytes()
        return files

    def test_allowlist_accepts_supported_source_locations(self):
        names = ["README.md", "VERSION", ".gitignore", ".gitattributes",
                 "requirements-analysis.txt", "docs/status.md", "scripts/verify.py",
                 "tests/test_release.py", ".github/workflows/release.yml",
                 "research/probe.py", "research/probe.ps1", "research/probe.js",
                 "research/status.md", "research/ghidra-scripts/Probe.java",
                 "research/fixtures/verified-result.json"]
        for name in names:
            with self.subTest(name=name):
                self.assertEqual(verify.audit_entry(name, b"text\n"), name)

    def test_allowlist_rejects_tools_secrets_binaries_and_nested_research(self):
        names = ["research/tools/run.py", "research/samples/sample.exe", ".env",
                 "docs/.env", "scripts/token.pem", "scripts/helper.exe",
                 "tests/__pycache__/test.pyc", "research/fixtures/probe.txt",
                 "research/decompiled/Probe.java", "other.py"]
        for name in names:
            with self.subTest(name=name), self.assertRaises(verify.SourceError):
                verify.audit_entry(name, b"text\n")

    def test_allowlist_rejects_path_traversal_and_platform_ambiguous_names(self):
        for name in ("../README.md", "/README.md", "C:/README.md", "docs/../README.md",
                     "docs\\README.md", "docs//file.md", "docs/./file.md",
                     "docs/file.md:stream", "docs/CON.md", "docs/file.md "):
            with self.subTest(name=name), self.assertRaises(verify.SourceError):
                verify.audit_entry(name, b"text\n")

    def test_allowlist_rejects_large_nontext_and_symlink_entries(self):
        for data in (b"x" * (verify.MAX_FILE_BYTES + 1), b"text\x00binary", b"\xff\xfe"):
            with self.assertRaises(verify.SourceError):
                verify.audit_entry("docs/status.md", data)
        with self.assertRaises(verify.SourceError):
            verify.audit_entry("docs/status.md", b"text", is_symlink=True)

    def test_manifest_rejects_tampering_and_duplicate_paths(self):
        self.manifest({"README.md": b"original"})
        self.write("README.md", b"modified")
        with self.assertRaises(verify.SourceError):
            verify.collect_sources(self.root)
        self.manifest({"README.md": b"original"})
        manifest_path = self.root / "MANIFEST.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["files"].append(manifest["files"][0])
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaises(verify.SourceError):
            verify.collect_sources(self.root)

    def test_manifest_cannot_escape_archive_root(self):
        self.manifest({"README.md": b"original"})
        manifest_path = self.root / "MANIFEST.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["files"][0]["path"] = "../README.md"
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaises(verify.SourceError):
            verify.collect_sources(self.root)

    def test_malformed_manifest_is_reported_as_a_source_error(self):
        for invalid in ([], None, {"name": "tato-catch", "files": [None]},
                        {"name": "tato-catch", "files": [], "git_commit": "invalid"}):
            with self.subTest(manifest=invalid):
                self.write("MANIFEST.json", json.dumps(invalid).encode())
                with self.assertRaises(verify.SourceError):
                    verify.collect_sources(self.root)

    def test_verifier_checks_python_and_json_without_executing_sources(self):
        self.manifest({"research/probe.py": b"raise RuntimeError('do not execute')\n",
                       "research/fixtures/result.json": b'{"matched": true}\n'})
        summary = verify.verify_repository(self.root, check_node=False, check_powershell=False)
        self.assertEqual(summary["python"], 1)
        self.assertEqual(summary["json"], 1)
        self.manifest({"research/probe.py": b"this is invalid python!\n"})
        with self.assertRaises(verify.SourceError):
            verify.verify_repository(self.root, check_node=False, check_powershell=False)
        self.manifest({"research/fixtures/result.json": b"{not-json}"})
        with self.assertRaises(verify.SourceError):
            verify.verify_repository(self.root, check_node=False, check_powershell=False)

    @unittest.skipUnless(shutil.which("node"), "Node.js not installed")
    def test_node_checks_frida_module_binding_and_rejects_invalid_javascript(self):
        self.manifest({"research/probe.js": b"const module = Process.mainModule;\n"})
        summary = verify.verify_repository(self.root, check_powershell=False)
        self.assertEqual(summary["javascript"], 1)
        self.manifest({"research/probe.js": b"const = ;\n"})
        with self.assertRaises(verify.SourceError):
            verify.verify_repository(self.root, check_powershell=False)

    @unittest.skipUnless(shutil.which("pwsh") or shutil.which("powershell"), "PowerShell not installed")
    def test_powershell_is_parsed_without_running_probe_commands(self):
        self.manifest({"research/probe.ps1": b"throw 'Do not execute this source'\n"})
        summary = verify.verify_repository(self.root, check_node=False)
        self.assertEqual(summary["powershell"], 1)
        self.manifest({"research/probe.ps1": b"function {\n"})
        with self.assertRaises(verify.SourceError):
            verify.verify_repository(self.root, check_node=False)

    @unittest.skipUnless(shutil.which("git"), "Git not installed")
    def test_git_selection_ignores_untracked_sample_but_rejects_tracked_sample(self):
        self.write("README.md", b"source\n")
        subprocess.run(["git", "init", "--quiet", str(self.root)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(self.root), "add", "README.md"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=Release Test",
                        "-c", "user.email=release-test@example.invalid", "-c", "commit.gpgsign=false",
                        "commit", "--quiet", "-m", "Test source"], check=True, capture_output=True)
        self.write("research/samples/ignored.exe", b"x" * (verify.MAX_FILE_BYTES + 1))
        files, commit = verify.collect_sources(self.root)
        self.assertEqual(set(files), {"README.md"})
        self.assertEqual(len(commit), 40)
        subprocess.run(["git", "-C", str(self.root), "add", "research/samples/ignored.exe"],
                       check=True, capture_output=True)
        with self.assertRaises(verify.SourceError):
            verify.collect_sources(self.root)

    def test_archive_is_deterministic_and_has_per_file_hashes_and_checksum(self):
        self.manifest(self.sources())
        first = release.build_archive(self.root, output_dir=self.root / "one")
        second = release.build_archive(self.root, output_dir=self.root / "two")
        self.assertEqual(first.read_bytes(), second.read_bytes())
        expected = hashlib.sha256(first.read_bytes()).hexdigest()
        self.assertEqual((first.parent / "SHA256SUMS").read_text(), f"{expected}  {first.name}\n")
        with zipfile.ZipFile(first) as archive:
            names = archive.namelist()
            self.assertEqual(names, sorted(names))
            prefix = "tato-catch-0.1.0-alpha.1/"
            manifest = json.loads(archive.read(prefix + "MANIFEST.json"))
            self.assertEqual(manifest["git_commit"], "a" * 40)
            for item in manifest["files"]:
                data = archive.read(prefix + item["path"])
                self.assertEqual(item["sha256"], hashlib.sha256(data).hexdigest())
                self.assertEqual(item["size"], len(data))
            self.assertTrue(all(item.date_time == (1980, 1, 1, 0, 0, 0) for item in archive.infolist()))

    def test_extracted_archive_can_verify_and_rebuild_without_git(self):
        self.manifest(self.sources())
        original = release.build_archive(self.root, output_dir=self.root / "original")
        with zipfile.ZipFile(original) as archive:
            archive.extractall(self.root / "extract")
        extracted = self.root / "extract" / "tato-catch-0.1.0-alpha.1"
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run([sys.executable, "-B", str(extracted / "scripts/verify.py"),
                                 "--root", str(extracted), "--no-node", "--no-powershell"],
                                capture_output=True, text=True, env=env)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        result = subprocess.run([sys.executable, "-B", str(extracted / "scripts/build_release.py"),
                                 "--root", str(extracted)], capture_output=True, text=True, env=env)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        rebuilt = extracted / "dist" / original.name
        self.assertEqual(original.read_bytes(), rebuilt.read_bytes())

    def test_version_override_cannot_escape_destination_and_updates_archive_version(self):
        self.manifest(self.sources())
        for version in ("../outside", "1/2/3", "", "0.1.0/../../escape"):
            with self.subTest(version=version), self.assertRaises(verify.SourceError):
                release.build_archive(self.root, version=version, output_dir=self.root / "dist")
        archive_path = release.build_archive(self.root, version="0.2.0-alpha.2")
        with zipfile.ZipFile(archive_path) as archive:
            self.assertEqual(archive.read("tato-catch-0.2.0-alpha.2/VERSION"), b"0.2.0-alpha.2\n")
        self.assertEqual((self.root / "VERSION").read_bytes(), b"0.1.0-alpha.1\n")


if __name__ == "__main__":
    unittest.main()
