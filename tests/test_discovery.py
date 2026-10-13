import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from llm_forensics.discovery import match_rule
from llm_forensics.scanner import scan


class DiscoveryTests(unittest.TestCase):
    def test_windows_notation_independent_of_host(self):
        rule = match_rule(r"C:\Users\Alex\APPDATA\LOCAL\OLLAMA\server-1.log", "windows")
        self.assertEqual(rule.id, "ollama-windows-logs")
        self.assertEqual(match_rule("Users/Alex/AppData/Local/Ollama/server.log", "linux").runner, "unknown")

    def test_unix_case_is_preserved(self):
        self.assertIsNone(match_rule("home/alex/.OLLAMA/history", "linux"))
        self.assertEqual(match_rule("home/alex/.ollama/history", "linux").kind, "cli_history")

    def test_three_source_os_trees_on_same_host(self):
        for source_os, path, expected in [
            ("windows", "Users/Alex/AppData/Local/Ollama/server.log", "log"),
            ("macos", "Users/Alex/.ollama/logs/server.log", "log"),
            ("linux", "etc/systemd/system/ollama.service.d/override.conf", "configuration_text"),
        ]:
            with self.subTest(source_os=source_os), tempfile.TemporaryDirectory() as folder:
                file = Path(folder, path)
                file.parent.mkdir(parents=True)
                file.write_text('Environment="OLLAMA_MODELS=/external/models"')
                report = scan(folder, source_os=source_os)
                self.assertEqual(report["source_os"], source_os)
                finding = report["findings"][0]
                self.assertEqual(finding["artifact_type"], expected)
                self.assertEqual(finding["evidence_relative_path"], path)
                matched = [r for r in report["discovery_coverage"] if r["candidate_files"]]
                self.assertEqual(len(matched), 1)
                self.assertEqual(matched[0]["status"], "candidates_found")

    def test_configuration_path_not_followed(self):
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, ".lmstudio-home-pointer").write_text("/outside/evidence")
            report = scan(folder, source_os="macos")
            self.assertEqual(report["files_considered"], 1)
            self.assertEqual(report["findings"][0]["observations"][0]["text"], "/outside/evidence")

    def test_empty_scope_is_not_absence_claim(self):
        with tempfile.TemporaryDirectory() as folder:
            report = scan(folder, source_os="windows")
            self.assertTrue(all(r["status"] == "no_match_in_readable_scope" for r in report["discovery_coverage"]))

    def test_cli_records_source_os_and_refuses_in_evidence_output(self):
        with tempfile.TemporaryDirectory() as folder:
            evidence = Path(folder, "evidence")
            evidence.mkdir()
            output = Path(folder, "report")
            result = subprocess.run([sys.executable, "-m", "llm_forensics", str(evidence), "--source-os", "windows", "--output", str(output)], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads((output / "report.json").read_text())["source_os"], "windows")
            result = subprocess.run([sys.executable, "-m", "llm_forensics", str(evidence), "--output", str(evidence / "report")], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((evidence / "report").exists())
