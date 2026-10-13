import json,plistlib,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from llm_forensics.acquisition import acquire
from llm_forensics.scanner import scan

class MacReleaseTests(unittest.TestCase):
    def test_app_inventory_and_settings_omit_credentials(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            app=root/'Applications/Ollama.app/Contents/Info.plist';app.parent.mkdir(parents=True)
            app.write_bytes(plistlib.dumps({'CFBundleShortVersionString':'0.test','CFBundleIdentifier':'com.electron.ollama'}))
            settings=root/'.lmstudio/settings.json';settings.parent.mkdir();settings.write_text(json.dumps({'downloadsFolder':'/custom/models','hfDownloadToken':'secret-not-in-report','defaultContextLength':512}))
            report=scan(root,source_os='macos')
            self.assertEqual(len(report['findings']),2)
            self.assertNotIn('secret-not-in-report',json.dumps(report))
            self.assertIn('/custom/models',json.dumps(report))
    def test_custom_cli_acquisition_and_verify(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve();source=root/'relocated';source.mkdir();(source/'history').write_text('synthetic evidence')
            case=root/'case'
            command=[sys.executable,'-m','llm_forensics']
            r=subprocess.run(command+['--ollama-home',str(source),'--source-os','macos','--acquire','--output',str(case)],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr)
            report=json.loads((case/'report.json').read_text());self.assertEqual(report['findings'][0]['original_source_path'],str(source/'history'))
            r=subprocess.run(command+['--verify-case',str(case)],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr)
            entry=json.loads((case/'acquisition-manifest.json').read_text())['files'][0]
            (case/entry['case_path']).unlink()
            r=subprocess.run(command+['--verify-case',str(case)],capture_output=True,text=True)
            self.assertEqual(r.returncode,1)
    def test_permission_failure_is_explicit(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve();source=root/'.ollama';source.mkdir();(source/'history').write_text('test')
            with patch('llm_forensics.acquisition.read_stable',side_effect=PermissionError('controlled denied read')):
                report=acquire([(source,None)],root/'case','macos',8192)
            self.assertEqual(report['status'],'partial')
            self.assertIn('controlled denied read',json.dumps(report['issues']))
    def test_strict_incomplete_exit(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve()
            r=subprocess.run([sys.executable,'-m','llm_forensics','--extra-path',str(root/'missing'),'--acquire','--strict','--output',str(root/'case')],capture_output=True,text=True)
            self.assertEqual(r.returncode,3,r.stderr)
            self.assertTrue((root/'case/report.json').exists())
    def test_record_limits_are_explicit(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);history=root/'.ollama/history';history.parent.mkdir();history.write_text('line\n'*10001)
            finding=scan(root)['findings'][0]
            self.assertEqual(finding['status'],'partial');self.assertEqual(len(finding['observations']),10000)
    def test_settings_and_plist_malformed_are_reported(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);p=root/'LM Studio.app/Contents/Info.plist';p.parent.mkdir(parents=True);p.write_bytes(b'not plist')
            self.assertEqual(scan(root,source_os='macos')['findings'][0]['status'],'parse_error')
