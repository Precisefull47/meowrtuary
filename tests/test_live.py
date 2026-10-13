import tempfile, unittest
from pathlib import Path
from llm_forensics.live import known_locations,scan_locations

class LiveTests(unittest.TestCase):
    def test_combines_locations_and_reports_absence(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve()
            a=root/'user/.ollama';a.mkdir(parents=True);(a/'history').write_text('test prompt\n')
            b=root/'user/.lmstudio';(b/'conversations').mkdir(parents=True)
            (b/'conversations/chat.json').write_text('{"messages":[{"role":"user","content":"hello"}]}')
            r=scan_locations([a,b,root/'missing'],'macos',root/'report',8192)
            self.assertEqual(len(r['findings']),2)
            self.assertEqual(len({f['id'] for f in r['findings']}),2)
            self.assertEqual(r['locations'][-1]['status'],'not_found')
    def test_output_inside_discovered_location_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve()
            with self.assertRaises(ValueError):scan_locations([root],'macos',root/'report',8192)
    def test_windows_log_directory_as_root(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve()
            logs=root/'Users/Alex/AppData/Local/Ollama';logs.mkdir(parents=True)
            (logs/'server.log').write_text('test log')
            r=scan_locations([logs],'windows',root/'report',8192)
            self.assertEqual(r['findings'][0]['artifact_type'],'log')
    def test_locations_are_profile_specific(self):
        p=Path('/synthetic/user')
        self.assertIn(p/'.ollama',known_locations(p,'linux'))
        self.assertIn(p/'AppData/Local/Ollama',known_locations(p,'windows'))
    def test_trash_is_explicit_opt_in(self):
        p=Path('/synthetic/user')
        self.assertNotIn(p/'.Trash',known_locations(p,'macos'))
        self.assertIn(p/'.Trash',known_locations(p,'macos',include_trash=True))
        self.assertNotIn(p/'.Trash',known_locations(p,'linux',include_trash=True))
