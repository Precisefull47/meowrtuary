import copy
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from llm_forensics.assessment import enrich,assess
from llm_forensics.acquisition import acquire
from llm_forensics.scanner import scan
from llm_forensics.comparison import compare,load_report
from llm_forensics.ground_truth import score
from llm_forensics.structured import loads,report_json
from llm_forensics.traversal import Budget
from llm_forensics.timeline import build_timeline
from llm_forensics.validation_kit import SCHEMA


class ReviewFixTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve()
        self.dbfile=self.root/'Library/Application Support/Ollama/db.sqlite';self.dbfile.parent.mkdir(parents=True)
    def tearDown(self):self.temp.cleanup()
    def database(self,count=1,carvable=False,wal=False):
        db=sqlite3.connect(self.dbfile)
        if wal:db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA wal_autocheckpoint=0')
        db.execute('CREATE TABLE chats(id TEXT,title TEXT)');db.execute("INSERT INTO chats VALUES('a','controlled')")
        db.execute(SCHEMA if carvable else 'CREATE TABLE messages(id INTEGER,chat_id TEXT,role TEXT,content TEXT,created_at TEXT)')
        db.executemany('INSERT INTO messages(id,chat_id,role,content,created_at) VALUES(?,?,?,?,?)',((i,'a','user',f'SYNTHETIC_{i}','2026-09-30T00:00:00Z') for i in range(count)))
        db.commit()
        return db
    def test_skipped_schema_recovery_partial_and_strict(self):
        self.database().close()
        r=enrich(scan(self.dbfile,recover_deleted=True))
        self.assertEqual(r['findings'][0]['recovery']['status'],'skipped')
        self.assertEqual(r['coverage_summary']['status'],'partial')
        result=subprocess.run([sys.executable,'-m','llm_forensics',str(self.dbfile),'--recover-deleted','--strict','--output',str(self.root/'out')],capture_output=True,text=True)
        self.assertEqual(result.returncode,3,result.stderr)
        written=json.loads((self.root/'out/report.json').read_text())
        self.assertTrue(written['analysis_options']['recover_deleted'])
        self.assertTrue(written['run_scope']['sources'])
    def test_wal_skipped_but_empty_success_not_gap(self):
        db=self.database(carvable=True,wal=True)
        try:
            r=enrich(scan(self.dbfile,recover_deleted=True))
            self.assertEqual(r['coverage_summary']['status'],'partial')
            self.assertIn('WAL',r['findings'][0]['recovery']['reason'])
        finally:db.close()
        r=enrich(scan(self.dbfile,recover_deleted=True))
        self.assertEqual(r['findings'][0]['recovery']['status'],'completed')
        self.assertEqual(r['findings'][0]['recovery']['records'],[])
        self.assertEqual(r['coverage_summary']['status'],'complete_within_scope')
    def test_10000_message_report_round_trip_compare_score(self):
        self.database(10000).close()
        r=enrich(scan(self.dbfile));r['timeline']=build_timeline(r)
        path=self.root/'report.json';path.write_text(report_json(r))
        loaded,_=load_report(path);self.assertEqual(len(loaded['findings'][0]['observations']),10000)
        self.assertEqual(compare(path,path)['summary'],{'unchanged':1})
        expected=self.root/'expected.json';expected.write_text(json.dumps({'schema_version':1,'scope':{'runner':'ollama','artifact_type':'desktop_sqlite','record_kind':'current'},'records':[{'role':'user','text':f'SYNTHETIC_{i}'} for i in range(10000)]}))
        self.assertTrue(score(expected,path)['exact_match'])
    def test_evidence_limit_stays_strict(self):
        with self.assertRaises(ValueError):loads(json.dumps([0]*200001))
    def comparison(self,a,b):
        x=self.root/'a.json';y=self.root/'b.json';x.write_text(json.dumps(a));y.write_text(json.dumps(b));return compare(x,y)['artifacts'][0]
    def test_options_do_not_claim_byte_change(self):
        self.database().close();a=scan(self.dbfile);b=copy.deepcopy(a)
        b['findings'][0]['recovery']={'status':'completed','records':[{'text':'historical'}]}
        result=self.comparison(a,b)
        self.assertEqual(result['status'],'indeterminate');self.assertEqual(result['source_bytes_status'],'unchanged')
        a['analysis_options']={'decode_requested':False};b=copy.deepcopy(a);b['analysis_options']={'decode_requested':True}
        self.assertEqual(self.comparison(a,b)['status'],'indeterminate')
    def test_analysis_changes_separate_from_source_changes(self):
        self.database().close();a=scan(self.dbfile);b=copy.deepcopy(a);b['findings'][0]['observations'][0]['text']='other'
        result=self.comparison(a,b);self.assertEqual(result['status'],'analysis_changed');self.assertEqual(result['source_bytes_status'],'unchanged')
        b['findings'][0]['sha256']='0'*64
        result=self.comparison(a,b);self.assertEqual(result['status'],'changed');self.assertEqual(result['source_bytes_status'],'changed')
    def test_budget_counts_nonmatching_entries_in_capture_and_scan(self):
        source=self.root/'scope';source.mkdir()
        for i in range(15):(source/f'{i}.unknown').write_text('ignored')
        (source/'empty').mkdir()
        budget=Budget(max_entries=5)
        m=acquire([(source,None)],self.root/'case','macos',8192,traversal_budget=budget)
        self.assertEqual(m['status'],'partial');self.assertEqual(m['scopes'][0]['status'],'incomplete')
        self.assertEqual(m['traversal']['entries_visited'],5)
        self.assertTrue(any(i['status']=='traversal_limit' for i in m['issues']))
        r=scan(source,traversal_budget=Budget(max_entries=5))
        self.assertTrue(any(i['status']=='traversal_limit' for i in r['issues']))
    def test_shared_scope_budget_and_timeout(self):
        sources=[]
        for i in range(2):
            p=self.root/f'scope{i}';p.mkdir();(p/'unknown').touch();sources.append((p,None))
        m=acquire(sources,self.root/'case','macos',8192,traversal_budget=Budget(max_entries=3))
        self.assertEqual(m['status'],'partial');self.assertEqual(m['traversal']['entries_visited'],3)
        budget=Budget(max_seconds=1)
        with patch('llm_forensics.traversal.time.monotonic',return_value=budget.started+2):
            r=scan(sources[0][0],traversal_budget=budget)
        self.assertIn('elapsed-time',r['issues'][0]['detail'])
