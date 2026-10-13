import io,json,tempfile,unittest,hashlib
from pathlib import Path
from unittest.mock import patch,Mock
from llm_forensics import menu as ui
from llm_forensics.output_location import browse_path
from llm_forensics.report_export import export_reports
from llm_forensics.case_package import seal_case,verify_package

class RefinementTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name).resolve()
        self.case=self.root/'case';self.case.mkdir();(self.case/'report.json').write_text('{"source_path":"/original/研究"}')
        (self.case/'report.html').write_text('<p>Original reference</p>');seal_case(self.case)
        self.quiet=patch('sys.stdout',new_callable=io.StringIO);self.quiet.start();self.addCleanup(self.quiet.stop)
    def test_native_file_command(self):
        with patch('llm_forensics.output_location.sys.platform','darwin'),patch('llm_forensics.output_location.subprocess.run',return_value=Mock(returncode=0,stdout=str(self.case/'report.json')+'\n')) as run:
            self.assertEqual(browse_path('file'),self.case/'report.json');self.assertIn('choose file',run.call_args.args[0][-1])
    def test_input_browse_folder(self):
        with patch.object(ui,'ask',return_value='1'),patch.object(ui,'browse_path',return_value=self.case):self.assertEqual(ui.source_path(kind='folder'),self.case)
    def test_input_browse_file(self):
        with patch.object(ui,'ask',return_value='2'),patch.object(ui,'browse_path',return_value=self.case/'report.json'):self.assertEqual(ui.source_path(),self.case/'report.json')
    def test_input_manual_retry(self):
        with patch.object(ui,'ask',side_effect=['3','', '3',str(self.case)]):self.assertEqual(ui.source_path(),self.case)
    def test_input_cancel(self):
        with patch.object(ui,'ask',return_value='1'),patch.object(ui,'browse_path',return_value=None):
            with self.assertRaises(ui.Back):ui.source_path()
    def test_input_failure_manual_fallback(self):
        with patch.object(ui,'ask',side_effect=['1','3',str(self.case)]),patch.object(ui,'browse_path',side_effect=OSError('Denied')):self.assertEqual(ui.source_path(),self.case)
    def test_export_preserves_source_and_references(self):
        before={p.name:p.read_bytes() for p in self.case.iterdir()};out=self.root/'export';result=export_reports(self.case,out)
        self.assertTrue(result['verified']);self.assertTrue(verify_package(out)['verified']);self.assertTrue(verify_package(self.case)['verified'])
        for name,data in before.items():self.assertEqual((self.case/name).read_bytes(),data)
        self.assertEqual((out/'report.json').read_bytes(),before['report.json'])
        self.assertFalse((out/'acquisition-manifest.json').exists())
    def test_export_rejects_inside_source(self):
        with self.assertRaises(ValueError):export_reports(self.case,self.case/'new')
    def test_export_no_overwrite(self):
        with self.assertRaises(FileExistsError):export_reports(self.case,self.root)
    def test_export_tampered_source_rejected(self):
        (self.case/'report.json').write_text('changed')
        with self.assertRaises(ValueError):export_reports(self.case,self.root/'out')
        self.assertFalse((self.root/'out').exists())
    def test_export_comparison_hashes(self):
        c=self.root/'comparison';c.mkdir();(c/'comparison.json').write_text('{}')
        out=self.root/'copies';self.assertTrue(export_reports(c,out)['verified'])
        info=json.loads((out/'report-export.json').read_text());self.assertFalse(info['source_integrity_verified']);self.assertFalse((out/'case-integrity.json').exists())
    def test_reports_open_does_not_prompt_destination(self):
        with patch.object(ui,'source_path',return_value=self.case),patch.object(ui,'ask',side_effect=['1',ui.Cancel()]),patch.object(ui,'open_report') as opened,patch.object(ui,'destination') as dest:
            with self.assertRaises(ui.Back):ui.reports_flow()
            opened.assert_called_once_with(self.case/'report.html');dest.assert_not_called()
    def test_reports_export_requires_explicit_yes(self):
        with patch.object(ui,'source_path',return_value=self.case),patch.object(ui,'ask',side_effect=['e',ui.Cancel()]),patch.object(ui,'destination',return_value=self.root/'out'),patch.object(ui,'yes',return_value=False),patch.object(ui,'run_job') as job:
            with self.assertRaises(ui.Back):ui.reports_flow()
            job.assert_not_called()
