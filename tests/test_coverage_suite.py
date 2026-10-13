import tempfile
import unittest
from pathlib import Path
from llm_forensics.live import known_locations, scan_locations
from llm_forensics.scanner import scan
from validation_suite import run_suite


class CoverageTests(unittest.TestCase):
    def test_ground_truth_matrix(self):
        result=run_suite()
        self.assertTrue(result['passed'],result)
        self.assertEqual(len(result['cases']),9)

    def test_live_file_scope_does_not_read_siblings(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve()
            source=root/'.zsh_history'
            source.write_text('echo unrelated\n"/tools/llama-cli" -p "synthetic prompt"\n',encoding='utf-8')
            (root/'.bash_history').write_text('llama-server --port 1234',encoding='utf-8')
            report=scan_locations([source],'macos',root/'report',8192)
            self.assertEqual(report['files_considered'],1)
            self.assertEqual(len(report['findings']),1)
            self.assertIn('synthetic prompt',report['findings'][0]['observations'][0]['text'])
            self.assertEqual(report['locations'][0]['status'],'scanned')

    def test_profile_file_discovery(self):
        profile=Path('/synthetic/profile')
        for system in ('macos','linux'):
            self.assertIn(profile/'.zsh_history',known_locations(profile,system))
            self.assertIn(profile/'.bash_history',known_locations(profile,system))
        self.assertIn(profile/'AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt',known_locations(profile,'windows'))
        self.assertIn(profile/'.lmstudio-home-pointer',known_locations(profile,'macos'))

    def test_input_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);source=root/'.zsh_history';source.write_text('llama-cli --help')
            alias=root/'alias'
            try:alias.symlink_to(source)
            except OSError:self.skipTest('Symlink creation unavailable')
            with self.assertRaises(ValueError):scan(alias)
