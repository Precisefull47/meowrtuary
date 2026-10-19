"""Action tests for shared submenu choices. Native OS adapters are isolated."""
import io, tempfile, unittest
from pathlib import Path
from unittest.mock import patch, Mock
from contextlib import nullcontext
from llm_forensics import menu as ui, menu_navigation as nav

class MenuAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.file=self.root/'evidence.txt';self.file.write_text('controlled')
        q=patch('sys.stdout',new_callable=io.StringIO);self.text=q.start();self.addCleanup(q.stop)
    def test_source_browse_each_type(self):
        for key,kind,path in [('1','folder',self.root),('2','file',self.file)]:
            with self.subTest(kind=kind),patch.object(ui,'ask',return_value=key),patch.object(ui,'browse_path',return_value=path) as browse:
                self.assertEqual(ui.source_path(),path);browse.assert_called_once_with(kind)
    def test_source_manual_folder_number_two(self):
        with patch.object(ui,'ask',side_effect=['2',str(self.root)]):self.assertEqual(ui.source_path(kind='folder'),self.root)
    def test_source_invalid_missing_retry(self):
        with patch.object(ui,'ask',side_effect=['99','3',str(self.root/'missing'),'3',str(self.file)]):self.assertEqual(ui.source_path(),self.file)
    def test_source_picker_cancel(self):
        for kind in ('folder','file'):
            with patch.object(ui,'ask',return_value='1' if kind=='folder' else '2'),patch.object(ui,'browse_path',return_value=None):
                with self.assertRaises(ui.Cancel):ui.source_path()
    def test_source_picker_failure_manual_fallback(self):
        with patch.object(ui,'ask',side_effect=['1','3',str(self.file)]),patch.object(ui,'browse_path',side_effect=OSError('unavailable')):
            self.assertEqual(ui.source_path(),self.file)
    def test_advanced_scan_yes_and_no(self):
        with patch.object(ui.sys,'platform','darwin'),patch.object(ui,'ask',side_effect=['a','y','y']):
            self.assertEqual(ui.scan_options(True),['--recover-deleted','--include-trash'])
        with patch.object(ui.sys,'platform','darwin'),patch.object(ui,'ask',side_effect=['a','n','n']):self.assertEqual(ui.scan_options(True),[])
    def test_advanced_offline_os_choices(self):
        for system in ('macos','windows','linux','unknown'):
            with patch.object(ui,'ask',side_effect=['a',system,'n']):self.assertEqual(ui.scan_options(False),['--source-os',system])
    def test_advanced_back_to_standard(self):
        with patch.object(ui.sys,'platform','darwin'),patch.object(ui,'ask',side_effect=['a',ui.Back(),'']):self.assertEqual(ui.scan_options(True),['--include-trash'])
    def test_options_vertical(self):
        ui.options([('1','First'),('2','Second')]);lines=self.text.getvalue().splitlines()
        self.assertEqual([line.strip() for line in lines if line.strip()],['1.  First','2.  Second','B Back   |   C Cancel'])
        self.assertNotIn('[1]', '\n'.join(lines))
    def test_result_details_report_and_back(self):
        (self.root/'report.html').write_text('controlled');(self.root/'report.json').write_text('{}')
        with patch.object(ui,'load_report',return_value=({'findings':[]},None)),patch('builtins.input',side_effect=['d','o','b']),patch.object(ui,'open_report') as opened,patch('llm_forensics.terminal.artifact_table',return_value='fixture') as table:
            ui.result_actions(self.root);opened.assert_called_once_with(self.root/'report.html');table.assert_called_once_with([])
    def test_result_settings_confirm_decline_back_failure(self):
        (self.root/'report.json').write_text('{}')
        for answers,called in [(['p','n','b'],False),(['p','b','b'],False),(['p','y','b'],True)]:
            with self.subTest(answers=answers),patch.object(ui,'load_report',return_value=({'findings':[]},None)),patch.object(ui,'has_access_denial',return_value=True),patch('builtins.input',side_effect=answers),patch.object(ui,'open_settings',side_effect=OSError('test failure')) as opened:
                ui.result_actions(self.root);self.assertEqual(opened.called,called)
    def test_report_browser_fallback(self):
        with patch.object(ui.webbrowser,'open',return_value=False) as opened:
            ui.open_report(self.file);opened.assert_called_once_with(self.file.resolve().as_uri());self.assertIn('Open this file',self.text.getvalue())
    def test_reports_open_each_file_and_invalid(self):
        (self.root/'report.html').write_text('controlled');(self.root/'report.json').write_text('{}')
        from llm_forensics.report_export import available_reports, REPORT_NAMES
        for name in REPORT_NAMES:(self.root/name).write_text('controlled')
        paths=available_reports(self.root)
        self.assertEqual(len(paths),11)
        with patch.object(ui,'source_path',return_value=self.root),patch.object(ui,'ask',side_effect=['99','']+[str(i+1) for i in range(len(paths))]+[ui.Cancel()]),patch.object(ui,'open_report') as opened:
            with self.assertRaises(ui.Cancel):ui.reports_flow()
            self.assertEqual([call.args[0] for call in opened.call_args_list],paths)
    def test_reports_back_selects_another_case(self):
        (self.root/'report.html').write_text('controlled')
        with patch.object(ui,'source_path',side_effect=[self.root,ui.Back()]) as source,patch.object(ui,'ask',side_effect=ui.Back):
            with self.assertRaises(ui.Back):ui.reports_flow()
            self.assertEqual(source.call_count,2)
    def test_reports_export_decline_runs_nothing(self):
        (self.root/'report.html').write_text('controlled')
        with patch.object(ui,'source_path',return_value=self.root),patch.object(ui,'ask',side_effect=['e','n',ui.Cancel()]),patch.object(ui,'destination',return_value=self.root/'unused'),patch.object(ui,'run_job') as job:
            with self.assertRaises(ui.Cancel):ui.reports_flow()
            job.assert_not_called()
    def test_result_invalid_does_not_execute(self):
        with patch('builtins.input',side_effect=['99','o','b']),patch.object(ui,'open_report') as opened:
            ui.result_actions(self.root);opened.assert_not_called()
    def test_raw_invalid_enter_does_not_launch(self):
        with patch.dict('os.environ',{'TERM':'xterm'}),patch.object(nav,'keys',return_value=nullcontext(1)),patch.object(nav,'read_key',side_effect=['9','9','enter','2','enter']):self.assertEqual(nav.choose(),'2')
    def test_raw_rapid_digits_do_not_launch_last_digit(self):
        with patch.dict('os.environ',{'TERM':'xterm'}),patch.object(nav,'keys',return_value=nullcontext(1)),patch.object(nav,'read_key',side_effect=['1','2','enter','q']):self.assertEqual(nav.choose(),'0')
    def test_raw_arrow_wrap(self):
        with patch.dict('os.environ',{'TERM':'xterm'}),patch.object(nav,'keys',return_value=nullcontext(1)),patch.object(nav,'read_key',side_effect=['up','enter','up','enter']):self.assertEqual(nav.choose(),'7')

    def test_interrupt_inside_workflow_returns_home(self):
        with patch('sys.stdin.isatty',return_value=True),patch('sys.stdout.isatty',return_value=True),patch.object(nav,'startup_graphic'),patch.object(nav,'choose',side_effect=['2','0']) as choose,patch.object(ui,'scan_flow',side_effect=KeyboardInterrupt):
            ui.menu();self.assertEqual(choose.call_count,2);self.assertIn('Operation cancelled',self.text.getvalue())

    def test_numbered_settings_choices(self):
        with patch.object(ui.sys,'platform','darwin'),patch.object(ui,'ask',return_value='1'):self.assertEqual(ui.scan_options(True),['--include-trash'])
        for key,system in [('1','macos'),('2','windows'),('3','linux'),('4','unknown')]:
            with patch.object(ui,'ask',side_effect=['2',key,'n']):self.assertEqual(ui.scan_options(False),['--source-os',system])
    def test_preflight_back(self):
        with patch.object(ui,'probe_access',return_value=[{'path':'fixture','status':'denied'}]),patch.object(ui,'ask',side_effect=ui.Back):
            with self.assertRaises(ui.Back):ui.access_preflight([])

    def test_cancel_each_shared_prompt(self):
        for action in [lambda:ui.source_path(),lambda:ui.destination('case'),lambda:ui.scan_options(True),lambda:ui.yes('Start')]:
            with patch('builtins.input',return_value='c'):
                with self.assertRaises(ui.Cancel):action()
    def test_offline_os_back_and_cancel(self):
        with patch.object(ui,'ask',side_effect=['2',ui.Back(),'1']):self.assertEqual(ui.scan_options(False),['--source-os','macos'])
        with patch.object(ui,'ask',side_effect=['2',ui.Cancel()]):
            with self.assertRaises(ui.Cancel):ui.scan_options(False)
