import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

from llm_forensics.report import render_html
from llm_forensics.scanner import scan


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, path, data):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data.encode() if isinstance(data, str) else data)
        return target

    def test_history_keeps_provenance_without_fabricating_times(self):
        p = self.write("user/.ollama/history", "hello\nexplain recursion\n")
        before = p.read_bytes()
        f = scan(self.root)["findings"][0]
        self.assertEqual(f["sha256"], hashlib.sha256(before).hexdigest())
        self.assertEqual(f["observations"][1]["record_locator"], "line 2")
        self.assertIsNone(f["observations"][0]["timestamp"])
        self.assertEqual(before, p.read_bytes())

    def test_unknown_schema_is_not_empty_chat(self):
        self.write(".lmstudio/conversations/x.json", '{"unfamiliar": [1, 2]}')
        self.assertEqual(scan(self.root)["findings"][0]["status"], "unsupported_schema")

    def test_messages_are_escaped_in_report(self):
        self.write(".lmstudio/conversations/x.json", json.dumps({"messages": [{"role": "user", "content": "<script>alert(1)</script>"}]}))
        report = scan(self.root)
        self.assertEqual(report["findings"][0]["observations"][0]["record_locator"], "/messages/0")
        rendered = render_html(report)
        self.assertNotIn("<script>alert(1)</script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)

    def test_bad_json_and_oversize_reported(self):
        self.write(".lmstudio/conversations/bad.json", "{bad")
        self.write(".ollama/history", "x" * 100)
        statuses = {f["status"] for f in scan(self.root, max_bytes=20)["findings"]}
        self.assertEqual(statuses, {"parse_error", "size_limit"})

    def test_symlinks_not_followed(self):
        self.write("outside/history", "not evidence")
        folder = self.root / ".ollama"
        folder.mkdir()
        try:
            (folder / "history").symlink_to(self.root / "outside/history")
        except OSError:
            self.skipTest("Symlink creation unavailable")
        result = scan(self.root)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["issues"][0]["status"], "symlink_skipped")

    def test_gguf_is_indicator_not_attribution(self):
        self.write("models/model.gguf", b"GGUF" + struct.pack("<IQQ", 3, 10, 8))
        f = scan(self.root)["findings"][0]
        self.assertEqual(f["runner"], "unknown")
        self.assertEqual(f["status"], "header_only")
        self.assertIn("not whole model", f["hash_scope"])

    def test_shell_history_and_direct_root(self):
        self.write(".bash_history", 'echo hello\n./llama-cli -m model.gguf -p "hi"\n')
        f = scan(self.root)["findings"][0]
        self.assertEqual(len(f["observations"]), 1)
        self.write(".ollama/history", "hello")
        self.assertEqual(scan(self.root / ".ollama")["findings"][0]["artifact_type"], "cli_history")

    def test_manifest_retains_layer_references(self):
        self.write(".ollama/models/manifests/registry.ollama.ai/library/demo/latest", '{"schemaVersion":2,"layers":[{"digest":"sha256:example"}]}')
        f = scan(self.root)["findings"][0]
        self.assertEqual(f["observations"][0]["layers"][0]["digest"], "sha256:example")


if __name__ == "__main__":
    unittest.main()
