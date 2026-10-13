import io,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch,Mock
from llm_forensics import menu as ui
from llm_forensics.permission_help import probe_access
from llm_forensics.menu_navigation import choose,screen

class AccessPreflightTests(unittest.TestCase):
    def setUp(self):
        self.quiet=patch('sys.stdout',new_callable=io.StringIO);self.quiet.start();self.addCleanup(self.quiet.stop)
    def test_all_main_operations(self):
        text=screen()+screen(more='cases')+screen(more='diagnostics')
        for label in ('Scan this Mac','Analyze evidence','Open a case','Verify case integrity','Compare two cases','Export reports','Package a case','Runtime diagnostics','Synthetic validation'):
            self.assertIn(label,text)
    def test_each_operation_separate_line(self):
        for line in screen().splitlines():self.assertLessEqual(line.count('['),1)
    def test_invalid_plain_navigation(self):
        with patch.dict(os.environ,{'TERM':'dumb'}),patch('builtins.input',side_effect=['4','b','99','','4','1']):self.assertEqual(choose(),'4')
    def test_denied_trash(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'.Trash';path.mkdir();path.chmod(0)
            try:self.assertEqual(probe_access([path])[0]['status'],'denied')
            finally:path.chmod(0o700)
    def test_readable_and_missing(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);file=root/'file';file.write_text('untouched')
            rows=probe_access([root,file,root/'missing']);self.assertEqual([r['status'] for r in rows],['readable','readable','not_found']);self.assertEqual(file.read_text(),'untouched')
    def test_no_follow_links(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);link=root/'link';link.symlink_to(root)
            self.assertEqual(probe_access([link])[0]['status'],'unsupported_path')
    def test_accessible_no_prompts(self):
        with patch.object(ui,'probe_access',return_value=[{'status':'readable','path':'/fixture'}]),patch.object(ui,'ask') as ask,patch.object(ui,'open_settings') as opened:
            ui.access_preflight([]);ask.assert_not_called();opened.assert_not_called()
    def test_blocked_cannot_silently_continue(self):
        with patch.object(ui,'probe_access',return_value=[{'status':'denied','path':'/fixture/.Trash'}]),patch.object(ui,'ask',side_effect=['',ui.Cancel()]),patch.object(ui,'run_job') as job:
            with self.assertRaises(ui.Cancel):ui.access_preflight([])
            job.assert_not_called()
    def test_settings_then_successful_recheck(self):
        with patch.object(ui,'probe_access',side_effect=[[{'status':'denied','path':'/fixture'}],[{'status':'denied','path':'/fixture'}],[{'status':'readable','path':'/fixture'}]]),patch.object(ui,'ask',side_effect=['s','r']),patch.object(ui,'open_settings') as opened:
            ui.access_preflight([]);opened.assert_called_once()
    def test_explicit_limited_choice(self):
        with patch.object(ui,'probe_access',return_value=[{'status':'denied','path':'/fixture'}]),patch.object(ui,'ask',return_value='l'),patch.object(ui,'open_settings') as opened:
            ui.access_preflight([]);opened.assert_not_called()
    def test_trash_in_standard_macos_scan(self):
        with patch.object(ui.sys,'platform','darwin'),patch.object(ui,'ask',return_value=''):self.assertIn('--include-trash',ui.scan_options(True))
    def test_offline_not_affected(self):
        with patch.object(ui,'ask',return_value=''):self.assertNotIn('--include-trash',ui.scan_options(False))
