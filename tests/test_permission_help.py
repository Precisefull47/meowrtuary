import io,unittest
from unittest.mock import patch,Mock
from llm_forensics import permission_help as help
from llm_forensics import menu

class PermissionHelpTests(unittest.TestCase):
    def report(self,detail):return {'coverage_summary':{'gaps':[{'status':'inaccessible','detail':detail}]}}
    def test_operation_not_permitted(self):
        with patch.object(help.sys,'platform','darwin'):self.assertTrue(help.has_access_denial(self.report('[Errno 1] Operation not permitted')))
    def test_permission_denied(self):
        with patch.object(help.sys,'platform','darwin'):self.assertTrue(help.has_access_denial(self.report('[Errno 13] Permission denied')))
    def test_missing_file_is_not_permission_denial(self):
        with patch.object(help.sys,'platform','darwin'):self.assertFalse(help.has_access_denial(self.report('[Errno 2] No such file')))
    def test_other_host_no_macos_guidance(self):
        with patch.object(help.sys,'platform','linux'):self.assertFalse(help.has_access_denial(self.report('[Errno 13] Permission denied')))
    def test_guidance_qualifies_access(self):
        text=help.instructions();self.assertIn('may help',text);self.assertIn('NEW case',text);self.assertIn('does not guarantee',text);self.assertIn('broad access',text)
    def test_open_only_launches_settings(self):
        with patch.object(help.subprocess,'run',return_value=Mock(returncode=0)) as run:
            help.open_settings();self.assertEqual(run.call_args.args[0],['/usr/bin/open','x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles'])
    def test_settings_failure_actionable(self):
        with patch.object(help.subprocess,'run',return_value=Mock(returncode=1)):
            with self.assertRaisesRegex(OSError,'Apple menu'):help.open_settings()
    def test_results_do_not_open_settings_automatically(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as folder:
            output=Path(folder);(output/'report.json').write_text('{}')
            report=self.report('[Errno 1] Operation not permitted');report['findings']=[]
            with patch.object(menu,'load_report',return_value=(report,None)),patch.object(help.sys,'platform','darwin'),patch('builtins.input',return_value=''),patch.object(menu,'open_settings') as opened,patch('sys.stdout',new_callable=io.StringIO) as text:
                menu.result_actions(output);opened.assert_not_called();self.assertIn('P.  Access settings',text.getvalue())
