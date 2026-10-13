import io,unittest
from pathlib import Path
from unittest.mock import patch,Mock
from llm_forensics import menu as ui
from llm_forensics import menu_navigation as nav

class FinalUXTests(unittest.TestCase):
    def test_original_graphic(self):
        with patch('shutil.get_terminal_size',return_value=Mock(columns=80)),patch('sys.stdout',new_callable=io.StringIO) as out,patch.object(out,'isatty',return_value=True),patch.dict('os.environ',{'TERM':'xterm','LLF_REDUCED_MOTION':'1'}):nav.startup_graphic()
        for line in nav.LOGO:self.assertIn(line.rstrip(),out.getvalue())
        self.assertTrue(out.getvalue().isascii())
    def test_small_graphic_not_distorted(self):
        with patch('shutil.get_terminal_size',return_value=Mock(columns=12)),patch('sys.stdout',new_callable=io.StringIO) as out,patch.object(out,'isatty',return_value=True),patch.dict('os.environ',{'TERM':'xterm','LLF_REDUCED_MOTION':'1'}):nav.startup_graphic()
        self.assertTrue(out.getvalue().startswith('meowrtuary'));self.assertTrue(all(len(line)<12 for line in out.getvalue().splitlines()))
    def test_noninteractive_menu_no_graphic(self):
        with patch('sys.stdin.isatty',return_value=False),patch.object(nav,'startup_graphic') as graphic,patch('builtins.print'):ui.menu();graphic.assert_not_called()
    def test_startup_once(self):
        with patch('sys.stdin.isatty',return_value=True),patch('sys.stdout.isatty',return_value=True),patch.object(nav,'startup_graphic') as graphic,patch.object(nav,'choose',side_effect=['2','2','0']),patch.object(ui,'scan_flow',side_effect=ui.Cancel),patch('builtins.print'):
            ui.menu();graphic.assert_not_called()
    def test_back_preserves_prior_input(self):
        first=Mock(return_value='source');second=Mock(side_effect=['destination1','destination2']);confirm=Mock(side_effect=[ui.Back(),True])
        result=ui.gather([('source',first),('output',second),('confirm',confirm)])
        self.assertEqual(result,{'source':'source','output':'destination2','confirm':True});first.assert_called_once();self.assertEqual(second.call_count,2)
    def test_back_from_second_revisits_first(self):
        first=Mock(side_effect=['A','B']);second=Mock(side_effect=[ui.Back(),'C'])
        self.assertEqual(ui.gather([('first',first),('second',second)]),{'first':'B','second':'C'})
    def test_cancel_does_not_revisit(self):
        first=Mock(return_value='source');second=Mock(side_effect=ui.Cancel)
        with self.assertRaises(ui.Cancel):ui.gather([('first',first),('second',second)])
        first.assert_called_once();second.assert_called_once()
    def test_back_at_first_returns_home(self):
        with self.assertRaises(ui.Back):ui.gather([('first',Mock(side_effect=ui.Back))])
    def test_manual_back_returns_picker(self):
        with patch.object(ui,'ask',side_effect=['3',ui.Back(),'1']),patch.object(ui,'browse_path',return_value=Path('/tmp')),patch('builtins.print'):
            self.assertEqual(ui.source_path(),Path('/tmp'))
    def test_manual_output_back_returns_picker(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d,patch.object(ui,'ask',side_effect=['2',ui.Back(),'1']),patch.object(ui,'browse_folder',return_value=Path(d)),patch('builtins.print'):
            self.assertEqual(ui.destination('case').parent,Path(d).resolve())
    def test_cancel_prompt(self):
        with patch('builtins.input',return_value='c'):
            with self.assertRaises(ui.Cancel):ui.ask('Path')
    def test_header_does_not_clear_screen(self):
        with patch('sys.stdout',new_callable=io.StringIO) as out:ui.header('Analyze')
        self.assertNotIn('\x1b[2J',out.getvalue())
    def test_verify_checks_both_manifests(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            case=Path(d)
            for name in ('acquisition-manifest.json','case-integrity.json'):(case/name).write_text('{}')
            with patch('sys.stdin.isatty',return_value=True),patch('sys.stdout.isatty',return_value=True),patch.object(nav,'startup_graphic'),patch.object(nav,'choose',side_effect=['4','0']),patch.object(ui,'source_path',return_value=case),patch.object(ui,'run_job',return_value=(True,'')) as job,patch('builtins.input',return_value=''),patch('builtins.print'):
                ui.menu();self.assertEqual([call.args[0][0] for call in job.call_args_list],['--verify-case','--verify-package'])
