import json
import plistlib
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from llm_forensics.acquisition import acquire
from llm_forensics.case_package import seal_case, verify_package, bundle_case
from llm_forensics.scanner import scan
from llm_forensics.assessment import assess


class MacHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve()
    def tearDown(self):self.temp.cleanup()
    def case(self):
        case=self.root/'case';case.mkdir();(case/'report.json').write_text('{}');(case/'evidence').mkdir();return case
    def test_full_case_tamper_and_extra(self):
        case=self.case();self.assertTrue(seal_case(case)['verified'])
        (case/'report.json').write_text('{"changed":true}')
        self.assertFalse(verify_package(case)['verified'])
        (case/'report.json').write_text('{}');(case/'extra').write_text('unlisted')
        self.assertFalse(verify_package(case)['verified'])
    def test_relocation_and_bundle(self):
        import tarfile
        case=self.case();seal_case(case);result=bundle_case(case,self.root/'out')
        extracted=self.root/'unpacked'
        with tarfile.open(result['archive']) as tar:tar.extractall(extracted,filter='data')
        self.assertTrue(verify_package(extracted/'case')['verified'])
    def test_no_reseal_and_link_refused(self):
        case=self.case();seal_case(case)
        with self.assertRaises(FileExistsError):seal_case(case)
        (case/'link').symlink_to(self.root)
        with self.assertRaises(ValueError):verify_package(case)
    def test_unsafe_manifest_rejected(self):
        case=self.case();seal_case(case);m=case/'case-integrity.json';v=json.loads(m.read_text());v['files'][0]['path']='../escape';m.write_text(json.dumps(v))
        with self.assertRaises(ValueError):verify_package(case)
    def test_low_disk_recorded(self):
        source=self.root/'.ollama';source.mkdir();(source/'history').write_text('controlled')
        with patch('llm_forensics.acquisition.shutil.disk_usage',return_value=SimpleNamespace(free=0)):
            result=acquire([(source,None)],self.root/'capture','macos',8192)
        self.assertEqual(result['status'],'partial');self.assertIn('Insufficient free space',json.dumps(result))
    def test_interruption_manifest(self):
        source=self.root/'.ollama';source.mkdir();(source/'history').write_text('controlled')
        with patch('llm_forensics.acquisition.read_stable',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):acquire([(source,None)],self.root/'capture','macos',8192)
        self.assertEqual(json.loads((self.root/'capture/acquisition-manifest.json').read_text())['status'],'interrupted')
    def test_preferences_dates_no_secret_values(self):
        from datetime import datetime
        p=self.root/'Library/Preferences/com.electron.ollama.plist';p.parent.mkdir(parents=True)
        p.write_bytes(plistlib.dumps({'SULastCheckTime':datetime(2026,1,1),'token':'PRIVATE_TOKEN'}))
        result=scan(self.root,source_os='macos');serialized=json.dumps(result)
        self.assertNotIn('PRIVATE_TOKEN',serialized);self.assertIn('2026-01-01',serialized)
    def test_deep_json_and_binary_errors(self):
        p=self.root/'.lmstudio/conversations/chat.json';p.parent.mkdir(parents=True)
        for data in (b'['*2000+b']'*2000,b'\xff\x00',b'{invalid'):
            p.write_bytes(data);result=scan(self.root);self.assertEqual(result['findings'][0]['status'],'parse_error')
    def test_changed_read_not_complete(self):
        r={'findings':[{'source_path':'x','id':'1','status':'parsed','source_changed_during_read':True,'observations':[]}],'issues':[]}
        self.assertNotEqual(assess(r)['status'],'complete_within_scope')
    def test_large_collection_and_unknown_blocks(self):
        root=self.root/'.lmstudio/conversations';root.mkdir(parents=True)
        for i in range(250):
            (root/f'{i}.json').write_text(json.dumps({'messages':[{'versions':[{'role':'user','content':[{'type':'image','path':'/unfollowed/private'},{'type':'text','text':'controlled'}]}]}]}))
        result=scan(self.root);self.assertEqual(len(result['findings']),250)
        self.assertTrue(all(f['status']=='partial' and len(f['observations'])==1 for f in result['findings']))
