import json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from qa import run,repair
class QATests(unittest.TestCase):
    def test_missing_acceptance_never_ready(self):
        rows=[{'category':'unit','status':'PASS'},{'category':'actual_gui','status':'NOT TESTED'}]
        self.assertEqual(run.assess(rows)[:2],(True,False))
    def test_partial_never_passes(self):self.assertFalse(run.assess([{'category':'unit','status':'PASS'}],False)[0])
    def test_failure_blocks(self):self.assertFalse(run.assess([{'category':'packaged','status':'FAIL'}])[0])
    def test_snapshot_excludes_evidence_and_releases(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve()
            for name in ['llm_forensics/__main__.py','cases/case/report.json','dist/releases/archive.tar.gz','validation/private/report.json','tests/test_x.py']:
                p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('fixture')
            self.assertEqual({str(p.relative_to(root)) for p in run.source_files(root)},{'llm_forensics/__main__.py','tests/test_x.py'})
    def test_source_links_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();(root/'x.py').symlink_to('/etc/passwd')
            with self.assertRaises(ValueError):run.source_files(root)
    def test_write_results_never_overwrites(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'report.json';run.write_json(p,{'before':True})
            with self.assertRaises(FileExistsError):run.write_json(p,{'after':True})
            self.assertEqual(json.loads(p.read_text()),{'before':True})
    def test_repair_budget_persistent_and_requires_reproduction(self):
        with tempfile.TemporaryDirectory() as d:
            state=Path(d).resolve();runs=state/'runs';runs.mkdir();work=state/'worktrees/run';work.mkdir(parents=True)
            a={'run_id':'one','campaign':'abc','source_sha256':'same','workspace':str(work),'checks':[{'id':'unit','status':'FAIL'}]};b={**a,'run_id':'two'}
            pa=runs/'a.json';pb=runs/'b.json';pa.write_text(json.dumps(a));pb.write_text(json.dumps(b))
            with patch.object(repair,'STATE',state),patch.object(repair,'RUNS',runs),patch.object(repair,'git',return_value='qa/test'):
                with self.assertRaises(ValueError):repair.reserve(pa,pa,'unit','test')
                for n in range(3):self.assertTrue(repair.reserve(pa,pb,'unit','test').exists())
                with self.assertRaisesRegex(ValueError,'exhausted'):repair.reserve(pa,pb,'unit','test')
    def test_repair_refuses_missing_external_gate(self):
        with tempfile.TemporaryDirectory() as d:
            runs=Path(d).resolve();a={'run_id':'one','campaign':'abc','source_sha256':'same','checks':[{'id':'gui','status':'NOT TESTED'}]}
            pa=runs/'a';pb=runs/'b';pa.write_text(json.dumps(a));pb.write_text(json.dumps({**a,'run_id':'two'}))
            with patch.object(repair,'RUNS',runs):
                with self.assertRaises(ValueError):repair.reserve(pa,pb,'gui','test')
    def test_missing_category_cannot_be_ready(self):
        self.assertFalse(run.assess([{'category':'unit','status':'PASS'}])[1])
    def test_timeout_records_failure(self):
        import os,sys
        with tempfile.TemporaryDirectory() as d:
            result=run.execute([sys.executable,'-c','import time; time.sleep(20)'],Path(d),dict(os.environ),Path(d)/'log',.1)
            self.assertEqual(result['exit_code'],124);self.assertTrue(result['timed_out'])
            self.assertIn(result['cleanup_scope'],('process_group_only','observed_descendants_and_process_group'))
    def test_more_keyboard_back_does_not_trigger_action(self):
        from contextlib import nullcontext
        from llm_forensics import menu_navigation as nav
        import io
        with patch.dict('os.environ',{'TERM':'xterm'}),patch('sys.stdout',new_callable=io.StringIO),patch.object(nav,'keys',return_value=nullcontext(1)),patch.object(nav.select,'select',return_value=([1],[],[])),patch.object(nav,'read_key',side_effect=['4','enter','b','3','enter']):
            self.assertEqual(nav.choose(),'3')

    def test_distribution_snapshot_includes_inputs_not_private_outputs(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve()
            required={'LICENSE','packaging/install-local.sh','packaging/build_candidate.py','packaging/licenses/Python.txt','packaging/release-docs/README.md','packaging/homebrew-meowrtuary/Formula/meowrtuary.rb'}
            excluded={'packaging/cases/private.json','packaging/private.json','packaging/__pycache__/x.pyc','packaging/releases/test.tar.gz'}
            for name in required|excluded:
                p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('fixture')
            self.assertEqual({p.relative_to(root).as_posix() for p in run.source_files(root)},required)
    def test_packaging_links_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();(root/'packaging').mkdir()
            (root/'packaging/install-local.sh').symlink_to('/etc/passwd')
            with self.assertRaises(ValueError):run.source_files(root)
