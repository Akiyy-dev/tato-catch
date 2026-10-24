"""Configuration checks use synthetic files and never attach a client."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("probe_config", ROOT / "research/probe_config.py")
config = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(config)


class ProbeConfigurationTests(unittest.TestCase):
    def test_supported_filename_and_digest_are_both_required(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "Tatotalk.exe"
            target.write_bytes(b"synthetic executable for configuration test")
            expected = hashlib.sha256(target.read_bytes()).hexdigest()
            self.assertEqual(config.validate_target(target, expected), target.resolve())
            with self.assertRaisesRegex(ValueError, "changed"):
                config.validate_target(target)
            other = target.with_name("other.exe")
            other.write_bytes(target.read_bytes())
            with self.assertRaisesRegex(ValueError, "supported"):
                config.validate_target(other, expected)

    def test_runtime_path_is_json_encoded_and_not_written_to_public_source(self):
        source = "const TARGET_EXE = /*TARGET_EXE*/null;"
        # Construct a synthetic Windows-style value without embedding an absolute path.
        target = "Q:" + chr(92) + "test folder" + chr(92) + 'quote"name' + chr(92) + "Tatotalk.exe"
        bound = config.bind_probe(source, target)
        payload = bound.removeprefix("const TARGET_EXE = ").removesuffix(";")
        self.assertEqual(json.loads(payload), target)
        self.assertEqual(source, "const TARGET_EXE = /*TARGET_EXE*/null;")

    def test_missing_or_duplicate_configuration_placeholders_are_rejected(self):
        for source in ("const value = null;", "/*TARGET_EXE*/null\n/*TARGET_EXE*/null"):
            with self.subTest(source=source), self.assertRaises(ValueError):
                config.bind_probe(source, "Tatotalk.exe")

    def test_all_published_probe_scripts_fail_closed_without_runner_binding(self):
        scripts = list((ROOT / "research").glob("*.js"))
        self.assertGreaterEqual(len(scripts), 7)
        for path in scripts:
            with self.subTest(script=path.name):
                source = path.read_text(encoding="utf-8")
                self.assertEqual(source.count("/*TARGET_EXE*/null"), 1)
                self.assertIn("typeof TARGET_EXE !== 'string'", source)
                self.assertIn("TARGET_EXE.toLowerCase()", source)
                self.assertNotIn("/*TARGET_EXE*/null", config.bind_probe(source, "Tatotalk.exe"))

    def test_runner_requires_target_before_any_attachment(self):
        result = subprocess.run([sys.executable, "-B", str(ROOT / "research/run_windows_module_probe.py"),
                                 "--pid", "1"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--target-exe", result.stderr)


if __name__ == "__main__":
    unittest.main()
