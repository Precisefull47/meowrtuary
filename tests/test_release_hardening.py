import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from llm_forensics.acquisition import acquire,verify_case
from llm_forensics.case_package import seal_case,verify_package,bundle_case
from llm_forensics.scanner import scan
from llm_forensics.structured import loads
from llm_forensics.comparison import load_report
from llm_forensics.diagnostics import diagnose

class ReleaseHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve()
    def tearDown(self):self.temp.cleanup()
    def cli(self,*args):
        result=subprocess.run([sys.executable,'-m','llm_forensics',*map(str,args)],capture_output=True,text=True,timeout=20)
        self.assertNotIn('Traceback',result.stderr)
        return result
    def source(self):
        p=self.root/'.ollama/history';p.parent.mkdir();p.write_text('SYNTHETIC\n');return p
    def test_bad_manifest_shape(self):
        case=self.root/'case';case.mkdir();(case/'acquisition-manifest.json').write_text('[]')
        self.assertEqual(self.cli('--verify-case',case).returncode,1)
    def test_missing_explicit_is_not_complete(self):
        r=self.cli('--extra-path',self.root/'absent','--strict','--output',self.root/'out')
        self.assertEqual(r.returncode,3)
        self.assertEqual(json.loads((self.root/'out/report.json').read_text())['coverage_summary']['status'],'blocked')
    def test_duplicate_and_nonfinite_json_rejected(self):
        for text in ('{"content":1,"content":2}','[NaN]','[Infinity]','[1e999]'):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):loads(text)
    def test_surrogate_exports_do_not_fail(self):
        p=self.root/'.lmstudio/conversations/chat.json';p.parent.mkdir(parents=True)
        p.write_text('{"role":"user","content":"\\ud800"}')
        out=self.root/'case';r=self.cli(p,'--acquire','--format','both','--timeline','--export-conversations','--output',out)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(json.loads((out/'conversations.json').read_text())['records'][0]['text'],'\ud800')
        self.assertTrue(verify_package(out)['verified'])
    def test_fifo_in_capture_cannot_verify(self):
        p=self.source();case=self.root/'case';acquire([(p,None)],case,'macos',8192)
        os.mkfifo(case/'evidence/unlisted-fifo')
        self.assertFalse(verify_case(case)['verified'])
    def test_empty_seal_rejected(self):
        case=self.root/'case';case.mkdir();(case/'case-integrity.json').write_text('{"schema_version":1,"files":[],"directories":[]}')
        with self.assertRaises(ValueError):verify_package(case)
    def test_failed_seal_write_is_retryable(self):
        case=self.root/'case';case.mkdir();(case/'report.json').write_text('{}')
        with patch('llm_forensics.case_package.json.dump',side_effect=OSError('controlled disk full')):
            with self.assertRaises(OSError):seal_case(case)
        self.assertFalse((case/'case-integrity.json').exists())
        self.assertFalse(list(case.glob('*.pending')))
        self.assertTrue(seal_case(case)['verified'])
    def test_tampered_raw_cannot_be_sealed(self):
        p=self.source();case=self.root/'case';m=acquire([(p,None)],case,'macos',8192)
        (case/m['files'][0]['case_path']).write_text('changed');(case/'report.json').write_text('{}')
        with self.assertRaises(ValueError):seal_case(case)
        self.assertFalse((case/'case-integrity.json').exists())
    def test_parent_symlink_not_followed(self):
        p=self.source();link=self.root/'linked';link.symlink_to(p.parent,target_is_directory=True)
        with self.assertRaises(ValueError):scan(link/'history')
    def test_runtime_diagnostics(self):
        self.assertTrue(diagnose()['passed'])
        r=self.cli('--doctor');self.assertEqual(r.returncode,0);self.assertTrue(json.loads(r.stdout)['passed'])
    def test_conflicting_verification_options(self):
        self.assertEqual(self.cli('--verify-case',self.root,'--recover-deleted').returncode,2)
        self.assertEqual(self.cli('--doctor','--live').returncode,2)
    def test_empty_path_rejected_before_output(self):
        self.assertEqual(self.cli('','--output',self.root/'out').returncode,2)
        self.assertFalse((self.root/'out').exists())
    def test_malformed_report_nested_shape(self):
        p=self.root/'report.json';p.write_text(json.dumps({'tool':'Local LLM Forensics','findings':[],'issues':[1]}))
        with self.assertRaises(ValueError):load_report(p)
        self.assertEqual(self.cli('--compare',p,p,'--output',self.root/'out').returncode,1)
    def test_real_denied_evidence(self):
        p=self.source();p.chmod(0)
        try:
            r=self.cli(p,'--acquire','--strict','--output',self.root/'out')
            self.assertEqual(r.returncode,3,r.stderr)
        finally:p.chmod(0o600)
    def test_real_unwritable_output(self):
        p=self.source();parent=self.root/'locked';parent.mkdir();parent.chmod(0o500)
        try:self.assertEqual(self.cli(p,'--output',parent/'out').returncode,1)
        finally:parent.chmod(0o700)
    def test_bad_sqlite_content_and_time(self):
        p=self.root/'Library/Application Support/Ollama/db.sqlite';p.parent.mkdir(parents=True)
        db=sqlite3.connect(p);db.executescript("CREATE TABLE chats(id TEXT,title TEXT);CREATE TABLE messages(id INTEGER,chat_id TEXT,role TEXT,content,created_at TEXT);INSERT INTO messages VALUES(1,'a','user',42,'0001-01-01T00:00:00+14:00');")
        db.close();r=self.cli(p,'--timeline','--format','both','--strict','--output',self.root/'out')
        self.assertEqual(r.returncode,3,r.stderr)
    def test_modified_manifest_digest_rejected(self):
        case=self.root/'case';case.mkdir();(case/'report.json').write_text('{}');seal_case(case)
        p=case/'case-integrity.json';v=json.loads(p.read_text());v['files'][0]['sha256']='bad';p.write_text(json.dumps(v))
        with self.assertRaises(ValueError):verify_package(case)
