import copy
import json
from pathlib import Path
import tempfile
import unittest
from llm_forensics.assessment import assess, enrich
from llm_forensics.comparison import compare, render_comparison
from llm_forensics.validation_kit import run_kit
from llm_forensics.report import render_html


def fixture():
    return {'tool':'Local LLM Forensics','version':'1.1.0','evidence_root':'/fixtures','scan_finished_utc':'test','limitations':[],
        'issues':[],'findings':[{'id':'artifact-1','runner':'ollama','artifact_type':'cli_history','source_path':'/case/history',
        'original_source_path':'/original/history','evidence_relative_path':'history','sha256':'a'*64,'hash_scope':'complete',
        'status':'parsed','observations':[{'text':'controlled','record_locator':'line 1'}]}]}


class RefinementTests(unittest.TestCase):
    def test_complete_empty_and_missing_defaults(self):
        r=fixture();r['findings']=[];r['locations']=[{'path':'missing','status':'not_found'}]
        self.assertEqual(assess(r)['status'],'complete_within_scope')
        self.assertIn('absence',assess(r)['negative_result'])
    def test_partial_and_blocked(self):
        r=fixture();r['issues']=[{'status':'inaccessible','path':'/denied'}]
        self.assertEqual(assess(r)['status'],'partial')
        r['findings']=[];self.assertEqual(assess(r)['status'],'blocked')
    def test_partial_artifact_and_capture(self):
        r=fixture();r['findings'][0]['status']='partial'
        self.assertEqual(assess(r)['status'],'partial')
        r['findings'][0]['status']='parsed';r['acquisition']={'status':'partial'}
        self.assertEqual(assess(r)['status'],'partial')
    def test_record_trace_and_escaping(self):
        r=fixture();r['issues']=[{'status':'inaccessible','path':'<script>alert(1)</script>'}];enrich(r)
        ref=r['findings'][0]['observations'][0]['evidence_reference']
        self.assertEqual(ref['original_source_path'],'/original/history');self.assertEqual(ref['record_locator'],'line 1')
        html=render_html(r);self.assertIn('Scan coverage: partial',html);self.assertNotIn('<script>alert(1)</script>',html)
    def comparison(self,a,b):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();x=root/'before.json';y=root/'after.json'
            x.write_text(json.dumps(a));y.write_text(json.dumps(b));return compare(x,y)
    def test_relocation_and_provenance_do_not_create_change(self):
        a=fixture();b=copy.deepcopy(a);b['findings'][0]['source_path']='/newcase/history';enrich(b)
        self.assertEqual(self.comparison(a,b)['summary'],{'unchanged':1})
    def test_changed_duplicate_record_counts(self):
        a=fixture();b=copy.deepcopy(a);b['findings'][0]['sha256']='b'*64;b['findings'][0]['observations']*=2
        result=self.comparison(a,b);self.assertEqual(result['summary'],{'changed':1});self.assertEqual(result['artifacts'][0]['newly_observed_records'],1)
    def test_missing_not_deleted_and_new(self):
        a=fixture();b=copy.deepcopy(a);b['findings'][0]['original_source_path']='/new/history'
        result=self.comparison(a,b);self.assertEqual(result['summary'],{'newly_observed':1,'not_observed_after':1})
        self.assertIn('does not mean deleted',render_comparison(result))
    def test_duplicates_are_ambiguous(self):
        a=fixture();b=copy.deepcopy(a);b['findings']*=2
        self.assertEqual(self.comparison(a,b)['summary'],{'ambiguous':1})
    def test_partial_and_version_change_indeterminate(self):
        a=fixture();b=copy.deepcopy(a);b['findings'][0]['status']='partial'
        self.assertEqual(self.comparison(a,b)['summary'],{'indeterminate':1})
        b=copy.deepcopy(a);b['version']='other';self.assertEqual(self.comparison(a,b)['summary'],{'indeterminate':1})
    def test_sidecar_change_not_unchanged(self):
        a=fixture();b=copy.deepcopy(a)
        a['findings'][0]['acquisition_files']=[{'source_path':'db-wal','sha256':'a','size_bytes':1}]
        b['findings'][0]['acquisition_files']=[{'source_path':'db-wal','sha256':'b','size_bytes':1}]
        self.assertEqual(self.comparison(a,b)['summary'],{'changed':1})
    def test_kit_exact_metrics(self):
        with tempfile.TemporaryDirectory() as d:
            result=run_kit(Path(d)/'kit');self.assertTrue(result['passed'],result)
            self.assertGreaterEqual(len(result['checks']),13)
            for check in result['checks']:self.assertTrue(check['exact_match'])

    def test_independent_ground_truth_multiset_and_scope(self):
        from llm_forensics.ground_truth import score
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();r=root/'report.json';e=root/'expected.json'
            r.write_text(json.dumps(fixture()))
            e.write_text(json.dumps({'schema_version':1,'scope':{'runner':'ollama','artifact_type':'cli_history','record_kind':'current'},'records':[{'text':'controlled'},{'text':'controlled'}]}))
            result=score(e,r);self.assertEqual(result['matched_records'],1);self.assertEqual(result['missed_records'],1);self.assertEqual(result['unexpected_records'],0);self.assertEqual(result['recall'],0.5)
