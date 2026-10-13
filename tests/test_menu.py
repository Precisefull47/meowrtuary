import io
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from llm_forensics import menu as ui


class MenuTests(unittest.TestCase):
    def setUp(self):
        preflight=patch.object(ui,"access_preflight");preflight.start();self.addCleanup(preflight.stop)

    def test_drag_drop_path_not_shell_evaluation(self):
        self.assertEqual(str(ui.path_value('/tmp/my\\ case')), str(Path('/tmp/my case').absolute()))
        self.assertIn('$(touch',str(ui.path_value('/tmp/$(touch malicious)')))
    def test_back_and_yes_validation(self):
        with patch('builtins.input',return_value='b'):
            with self.assertRaises(ui.Back):ui.ask('path')
        with patch('builtins.input',side_effect=['maybe','yes']),patch('sys.stdout',new_callable=io.StringIO):
            self.assertTrue(ui.yes('continue'))
    def test_confirmation_requires_explicit_answer(self):
        with patch('builtins.input',side_effect=['', '   ', 'maybe', 'Y']) as prompt, patch('sys.stdout',new_callable=io.StringIO):
            self.assertTrue(ui.yes('Start'))
            self.assertEqual(prompt.call_count,4)
        with patch('builtins.input',side_effect=['', 'n']), patch('sys.stdout',new_callable=io.StringIO):
            self.assertFalse(ui.yes('Start'))
        with patch('builtins.input',return_value='b'):
            with self.assertRaises(ui.Back):ui.yes('Start')

    def test_blank_start_never_launches_scan(self):
        with patch('llm_forensics.menu.sys.platform','darwin'), patch.object(ui,'header'), patch('builtins.print'), patch.object(ui,'destination',return_value=Path('/tmp/unused-case')), patch('builtins.input',side_effect=['','','n']) as prompt, patch.object(ui,'run_job') as run:
            ui.scan_flow(True)
            self.assertEqual(prompt.call_count,3)
            run.assert_not_called()

    def test_plain_output_has_no_ansi(self):
        with patch('sys.stdout',new_callable=io.StringIO):self.assertEqual(ui.styled('text'),'text')
        self.assertNotIn('\x1b',ui.safe('file\x1b[2J\nname'))
    def test_noninteractive_menu_does_not_read(self):
        with patch('sys.stdin.isatty',return_value=False),patch('sys.stdout',new_callable=io.StringIO) as out,patch('builtins.input',side_effect=AssertionError('must not prompt')):
            ui.menu();self.assertIn('interactive terminal',out.getvalue())
    def test_menu_exit_and_invalid_choice(self):
        with patch('sys.stdin.isatty',return_value=True),patch('sys.stdout.isatty',return_value=True),patch.object(ui,'header'),patch('llm_forensics.menu_navigation.choose',side_effect=['bad','0']),patch('builtins.input',return_value=''),patch('builtins.print'):
            ui.menu()
    def test_scan_builds_expected_arguments(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'new case'
            with patch('llm_forensics.menu.sys.platform','darwin'),patch.object(ui,'header'),patch('builtins.print'),patch.object(ui,'ask',return_value='a'),patch.object(ui,'yes',side_effect=[True,False,True]),patch.object(ui,'destination',return_value=out),patch.object(ui,'run_job',return_value=(True,'')) as run,patch.object(ui,'result_actions') as result:
                ui.scan_flow(True)
                arguments=run.call_args_list[0].args[0]
                self.assertIn('--live',arguments);self.assertIn('--acquire',arguments);self.assertIn('--recover-deleted',arguments)
                self.assertIn('--timeline',arguments);self.assertIn('--format',arguments);result.assert_called_once_with(out)
    def test_existing_parent_creates_unique_child(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(ui,'ask',side_effect=['2',d,'y']),patch('builtins.print'):
                output=ui.destination('test')
                self.assertEqual(output.parent,Path(d).resolve())
                self.assertFalse(output.exists())
    def test_job_real_success_and_failure(self):
        with patch('sys.stdout',new_callable=io.StringIO):
            ok,_=ui.run_job(['--version'],'Checking');self.assertTrue(ok)
            ok,_=ui.run_job(['--not-a-real-option'],'Checking');self.assertFalse(ok)
    def test_interrupt_stops_owned_child(self):
        from unittest.mock import Mock
        process=Mock();process.poll.return_value=None
        with patch('llm_forensics.menu.subprocess.Popen',return_value=process),patch('llm_forensics.menu.time.sleep',side_effect=KeyboardInterrupt),patch.object(ui,'stop_child') as stop,patch('sys.stdout',new_callable=io.StringIO):
            with self.assertRaises(ui.Back):ui.run_job(['--version'],'Checking')
            stop.assert_called_once_with(process)
