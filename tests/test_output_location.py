import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch, Mock
from llm_forensics import menu as ui
from llm_forensics import output_location as loc


class LocationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()
        self.stdout=patch('sys.stdout',new_callable=io.StringIO);self.stdout.start();self.addCleanup(self.stdout.stop)
        ui._selected_outputs.clear()

    def dialog(self,stdout='',returncode=0):
        return patch.object(loc.subprocess,'run',return_value=Mock(stdout=stdout,stderr='test failure',returncode=returncode))

    def test_native_unicode_space_preserved(self):
        with patch.object(loc.sys,'platform','darwin'),self.dialog('/tmp/研究 reports /\n') as run:
            self.assertEqual(loc.browse_folder(),Path('/tmp/研究 reports '))
            self.assertEqual(run.call_args.args[0][0],'/usr/bin/osascript')
            self.assertNotIn('shell',run.call_args.kwargs)

    def test_native_cancel(self):
        with patch.object(loc.sys,'platform','darwin'),self.dialog('\n'):
            self.assertIsNone(loc.browse_folder())

    def test_native_failure(self):
        with patch.object(loc.sys,'platform','darwin'),self.dialog(returncode=1):
            with self.assertRaisesRegex(OSError,'manual'):loc.browse_folder()

    def test_native_timeout(self):
        with patch.object(loc.sys,'platform','darwin'),patch.object(loc.subprocess,'run',side_effect=subprocess.TimeoutExpired('osascript',300)):
            with self.assertRaisesRegex(OSError,'timed out'):loc.browse_folder()

    def test_non_macos_manual_fallback(self):
        with patch.object(loc.sys,'platform','linux'):
            with self.assertRaises(OSError):loc.browse_folder()

    def test_invalid_native_result(self):
        with patch.object(loc.sys,'platform','darwin'),self.dialog('relative\n'):
            with self.assertRaises(OSError):loc.browse_folder()

    def test_manual_destination_confirm(self):
        parent=self.root/'研究 reports';parent.mkdir()
        with patch.object(ui,'ask',side_effect=['2',str(parent),'','y']):out=ui.destination('case')
        self.assertEqual(out.parent,parent);self.assertFalse(out.exists())

    def test_suggested_destination(self):
        with patch.object(ui.Path,'home',return_value=self.root),patch.object(ui,'ask',side_effect=['3','y']):out=ui.destination('case')
        self.assertEqual(out.parent,self.root)

    def test_browse_destination(self):
        with patch.object(ui,'browse_folder',return_value=self.root),patch.object(ui,'ask',side_effect=['1','y']):out=ui.destination('case')
        self.assertEqual(out.parent,self.root)

    def test_browse_cancel_starts_nothing(self):
        with patch.object(ui,'browse_folder',return_value=None),patch.object(ui,'ask',return_value='1'):
            with self.assertRaises(ui.Back):ui.destination('case')
        self.assertEqual(list(self.root.iterdir()),[]);self.assertEqual(ui._selected_outputs,{})

    def test_picker_failure_then_manual(self):
        with patch.object(ui,'browse_folder',side_effect=OSError('Unavailable')),patch.object(ui,'ask',side_effect=['1','2',str(self.root),'y']):out=ui.destination('case')
        self.assertEqual(out.parent,self.root)

    def test_back_creates_nothing(self):
        with patch('builtins.input',return_value='b'):
            with self.assertRaises(ui.Back):ui.destination('case')
        self.assertEqual(list(self.root.iterdir()),[])

    def test_destination_selection_does_not_create_output(self):
        with patch.object(ui,'ask',side_effect=['2',str(self.root)]):out=ui.destination('case')
        self.assertFalse(out.exists())

    def test_invalid_manual_reprompt(self):
        with patch.object(ui,'ask',side_effect=['2',str(self.root/'missing'),'2',str(self.root),'y']):out=ui.destination('case')
        self.assertEqual(out.parent,self.root)

    def test_readonly_parent(self):
        self.root.chmod(0o500)
        try:
            with self.assertRaises(PermissionError):loc.validate_parent(self.root)
        finally:self.root.chmod(0o700)

    def test_inaccessible_parent(self):
        with patch.object(loc.os,'access',return_value=False):
            with self.assertRaises(PermissionError):loc.validate_parent(self.root)

    def test_evidence_source_rejected(self):
        child=self.root/'child';child.mkdir()
        for path in (self.root,child):
            with self.assertRaises(ValueError):loc.validate_parent(path,[self.root])

    def test_symlink_into_evidence_rejected(self):
        link=self.root/'link';link.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(ValueError):loc.validate_parent(link,[self.root])

    def test_file_is_not_parent(self):
        f=self.root/'file';f.write_text('test')
        with self.assertRaises(ValueError):loc.validate_parent(f)

    def test_guarded_creation_and_no_overwrite(self):
        out=self.root/'case';guard=loc.output_guard(out)
        with patch.dict(os.environ,{loc.GUARD:guard}):
            loc.create_output(out)
            with self.assertRaises(FileExistsError):loc.create_output(out)
        self.assertEqual(out.stat().st_mode & 0o777,0o700)

    def test_disconnected_parent_not_recreated(self):
        parent=self.root/'volume';parent.mkdir();out=parent/'case';guard=loc.output_guard(out);parent.rmdir()
        with patch.dict(os.environ,{loc.GUARD:guard}):
            with self.assertRaises(OSError):loc.create_output(out)
        self.assertFalse(parent.exists())

    def test_replaced_volume_rejected(self):
        parent=self.root/'volume';parent.mkdir();guard=loc.output_guard(parent/'case');parent.rename(self.root/'old');parent.mkdir()
        with patch.dict(os.environ,{loc.GUARD:guard}):
            with self.assertRaisesRegex(OSError,'changed'):loc.check_storage()
        self.assertEqual(list(parent.iterdir()),[])

    def test_storage_loss_during_job_reported(self):
        parent=self.root/'volume';parent.mkdir();out=parent/'case';guard=loc.output_guard(out)
        with patch.dict(os.environ,{loc.GUARD:guard}):
            loc.create_output(out);parent.rename(self.root/'offline')
            with self.assertRaises(OSError):loc.check_storage()
        self.assertFalse(parent.exists())

    def test_resource_exhaustion_not_redirected(self):
        out=self.root/'case'
        with patch.dict(os.environ,{loc.GUARD:loc.output_guard(out)}),patch.object(loc.os,'mkdir',side_effect=OSError(28,'No space left')):
            with self.assertRaises(OSError):loc.create_output(out)
        self.assertFalse(out.exists())

    def test_scripted_parent_creation_unchanged(self):
        with patch.dict(os.environ,{},clear=True):loc.create_output(self.root/'new'/'case')
        self.assertTrue((self.root/'new/case').is_dir())

    def test_finder_is_optional(self):
        with patch.object(ui.sys,'platform','darwin'),patch('builtins.input',return_value=''),patch.object(ui.subprocess,'run') as run:
            ui.result_actions(self.root);run.assert_not_called()

    def test_finder_explicit_action(self):
        with patch.object(ui.sys,'platform','darwin'),patch('builtins.input',side_effect=['f','']),patch.object(ui.subprocess,'run',return_value=Mock(returncode=0)) as run:
            ui.result_actions(self.root);self.assertEqual(run.call_args.args[0],['/usr/bin/open',str(self.root)])

    def test_existing_case_parent_rejected(self):
        (self.root/'case-integrity.json').write_text('{}')
        child=self.root/'nested';child.mkdir()
        for parent in (self.root,child):
            with self.assertRaisesRegex(ValueError,'existing forensic cases'):loc.validate_parent(parent)
