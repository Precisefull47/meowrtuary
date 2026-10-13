import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from llm_forensics.timeline import build_timeline,normalize,epoch_ms,write_timeline
from llm_forensics.report import render_timeline


def finding(records,**kwargs):
    return {'id':'artifact-1','runner':'ollama','artifact_type':'desktop_sqlite','source_path':'/evidence/db.sqlite','sha256':'abc','hash_scope':'main database only','status':'parsed','observations':records,**kwargs}


class TimelineTests(unittest.TestCase):
    def test_offset_ordering_and_timezone_required(self):
        a={'record_locator':'row 1','role':'user','timestamp_raw':'2026-09-29T10:00:00+05:30','text':'first'}
        b={'record_locator':'row 2','role':'assistant','timestamp':'2026-09-29T05:00:00Z','text':'second'}
        c={'record_locator':'row 3','timestamp_raw':'2026-09-29T03:00:00','text':'unknown'}
        r=build_timeline({'findings':[finding([b,c,a])]})
        self.assertEqual([e['text'] for e in r['events']],['first','second'])
        self.assertEqual(r['events'][0]['timestamp_utc'],'2026-09-29T04:30:00.000000+00:00')
        self.assertEqual(r['undated_records'][0]['text'],'unknown')
    def test_file_time_not_assigned_to_messages(self):
        r=build_timeline({'findings':[finding([{'record_locator':'/0','text':'unknown'}],filesystem_mtime_utc='2026-09-29T05:00:00Z')]})
        self.assertEqual(r['events'][0]['event_kind'],'file_modified')
        self.assertIsNone(r['undated_records'][0]['timestamp_utc'])
    def test_residue_is_separate_and_duplicates_not_removed(self):
        row={'record_locator':'page 2','timestamp':'2026-09-29T05:00:00Z','text':'same','role':'user'}
        r=build_timeline({'findings':[finding([row],recovery={'records':[dict(row,current_record_comparison='matches current row')]})]})
        self.assertEqual(len(r['events']),2)
        self.assertEqual({e['event_kind'] for e in r['events']},{'historical_residue','message_record'})
        self.assertTrue(all(e['source_sha256']=='abc' for e in r['events']))
    def test_chat_metadata_does_not_timestamp_individual_records(self):
        f=finding([{'record_locator':'/messages/0','role':'user','text':'hello'}],conversation_metadata=[{'kind':'conversation_metadata','raw_fields':{'createdAt':0,'userLastMessagedAt':1000,'assistantLastMessagedAt':True}}])
        r=build_timeline({'findings':[f]})
        self.assertEqual([e['timestamp_utc'] for e in r['events']],['1970-01-01T00:00:00.000000+00:00','1970-01-01T00:00:01.000000+00:00'])
        self.assertEqual(len(r['undated_records']),2)
    def test_invalid_dates_and_epoch_bounds(self):
        for value in ('not a date','2026-01-01',None):self.assertIsNone(normalize(value))
        for value in (True,'1000',10**30):self.assertIsNone(epoch_ms(value))
    def test_csv_formula_protection_and_exact_json(self):
        texts=['=HYPERLINK("https://example.invalid")','  +1','@test','\tformula','normal, comma\nnewline']
        r=build_timeline({'findings':[finding([{'record_locator':str(i),'text':t} for i,t in enumerate(texts)])]})
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder);write_timeline(r,path)
            self.assertEqual([e['text'] for e in json.loads((path/'timeline.json').read_text())['undated_records']],texts)
            with (path/'timeline.csv').open(newline='') as handle:rows=list(csv.DictReader(handle))
            self.assertTrue(all(row['text'].startswith("'") for row in rows[:4]))
            self.assertEqual(rows[-1]['text'],texts[-1])
            self.assertIn('text',rows[0]['csv_escaped_fields'])
    def test_html_escape_and_display_limit(self):
        r=build_timeline({'findings':[finding([{'record_locator':str(i),'text':'<script>alert(1)</script>'} for i in range(501)])]})
        rendered=render_timeline(r)
        self.assertNotIn('<script>',rendered)
        self.assertIn('&lt;script&gt;',rendered)
        self.assertEqual(rendered.count('data-timeline-row'),500)
        self.assertIn('first 500',rendered)
        self.assertEqual(len(r['undated_records']),501)
    def test_cli_timeline_exports(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);evidence=root/'evidence/.ollama';evidence.mkdir(parents=True)
            (evidence/'history').write_text('synthetic input\n')
            out=root/'report'
            r=subprocess.run([sys.executable,'-m','llm_forensics',str(root/'evidence'),'--timeline','--format','both','--output',str(out)],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr)
            timeline=json.loads((out/'timeline.json').read_text())
            self.assertEqual(timeline['summary']['file_time_events'],1)
            self.assertEqual(timeline['summary']['undated_records'],1)
            self.assertTrue((out/'timeline.csv').exists())
            self.assertIn('Evidence timeline',(out/'report.html').read_text())
