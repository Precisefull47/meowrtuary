import hashlib,json,sqlite3,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from llm_forensics.acquisition import acquire,verify_case,read_stable
from llm_forensics.scanner import scan


class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve()
        self.source=self.root/'custom-home';self.source.mkdir();self.case=self.root/'case'
    def tearDown(self):self.temp.cleanup()
    def test_custom_home_capture_and_integrity(self):
        p=self.source/'conversations/chat.json';p.parent.mkdir();p.write_text('{"messages":[{"role":"user","content":"test"}]}')
        manifest=acquire([(self.source,'.lmstudio')],self.case,'macos',8192)
        self.assertEqual(manifest['status'],'complete')
        self.assertEqual(scan(self.case/'evidence',8192,'macos')['findings'][0]['observations'][0]['text'],'test')
        self.assertTrue(verify_case(self.case)['verified'])
        target=self.case/manifest['files'][0]['case_path'];target.write_text('tampered')
        self.assertFalse(verify_case(self.case)['verified'])
        self.assertIn('test',p.read_text())
    def test_wal_capture_preserves_current_rows(self):
        source=self.source/'Library/Application Support/Ollama/db.sqlite';source.parent.mkdir(parents=True)
        db=sqlite3.connect(source)
        try:
            db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA wal_autocheckpoint=0')
            db.executescript("CREATE TABLE chats(id TEXT,title TEXT);CREATE TABLE messages(id INTEGER,chat_id TEXT,role TEXT,content TEXT,created_at TEXT);INSERT INTO chats VALUES('one','test');INSERT INTO messages VALUES(1,'one','user','from WAL','2026-09-29T05:00:00Z');")
            before={p.name:p.read_bytes() for p in source.parent.iterdir()}
            m=acquire([(self.source,None)],self.case,'macos',1024*1024)
            self.assertEqual(m['status'],'complete')
            f=scan(self.case/'evidence',source_os='macos')['findings'][0]
            self.assertEqual(f['observations'][0]['text'],'from WAL')
            self.assertEqual(before,{p.name:p.read_bytes() for p in source.parent.iterdir()})
            self.assertTrue(verify_case(self.case)['verified'])
        finally:db.close()
    def test_changed_file_quarantined(self):
        p=self.source/'history';p.write_text('first')
        original=read_stable;calls=0
        def change(path,limit):
            nonlocal calls
            calls+=1
            if calls==2:p.write_text('second')
            return original(path,limit)
        with patch('llm_forensics.acquisition.read_stable',side_effect=change):m=acquire([(self.source,'.ollama')],self.case,'macos',8192)
        self.assertEqual(m['status'],'partial')
        self.assertEqual(m['files'][0]['status'],'quarantined')
        self.assertEqual(scan(self.case/'evidence')['findings'],[])
        self.assertTrue(verify_case(self.case)['verified'])
    def test_symlink_and_limit_explicit(self):
        p=self.source/'history';p.write_text('x'*100)
        m=acquire([(self.source,'.ollama')],self.case,'macos',16)
        self.assertEqual(m['status'],'partial');self.assertFalse(m['files'])
        other=self.root/'symlink'
        try:other.symlink_to(self.source,target_is_directory=True)
        except OSError:self.skipTest('Symlinks unavailable')
        m=acquire([(other,'.ollama')],self.root/'second-case','macos',1000)
        self.assertEqual(m['status'],'partial');self.assertFalse(m['files'])
    def test_nested_output_and_overwrite_rejected(self):
        with self.assertRaises(ValueError):acquire([(self.source,None)],self.source/'case','macos',8192)
        self.case.mkdir()
        with self.assertRaises(FileExistsError):acquire([(self.source,None)],self.case,'macos',8192)
    def test_manifest_escape_rejected(self):
        self.case.mkdir();(self.case/'acquisition-manifest.json').write_text(json.dumps({'schema_version':1,'files':[{'case_path':'../outside'}]}))
        with self.assertRaises(ValueError):verify_case(self.case)
    def test_unlisted_file_is_not_verified(self):
        (self.source/'history').write_text('known')
        acquire([(self.source,'.ollama')],self.case,'macos',8192)
        (self.case/'evidence/extra').write_text('unlisted')
        self.assertFalse(verify_case(self.case)['verified'])
    def test_rollback_journal_quarantines_database(self):
        source=self.source/'Library/Application Support/Ollama/db.sqlite';source.parent.mkdir(parents=True)
        db=sqlite3.connect(source);db.execute('CREATE TABLE t(x)');db.commit();db.close()
        Path(str(source)+'-journal').write_bytes(b'nonempty journal')
        m=acquire([(self.source,None)],self.case,'macos',1024*1024)
        self.assertEqual(m['status'],'partial')
        self.assertTrue(all(e['status']=='quarantined' for e in m['files']))
        self.assertFalse(scan(self.case/'evidence')['findings'])
    def test_model_header_capture_is_explicit(self):
        import struct
        model=self.source/'sample.gguf';raw=b'GGUF'+struct.pack('<IQQ',3,1,0)+b'x'*1000;model.write_bytes(raw)
        m=acquire([(self.source,None)],self.case,'macos',128)
        self.assertEqual(m['status'],'complete');entry=m['files'][0]
        self.assertEqual(entry['capture_mode'],'prefix');self.assertEqual(entry['size_bytes'],24)
        self.assertEqual(entry['source_size_bytes'],len(raw));self.assertTrue(verify_case(self.case)['verified'])
        self.assertEqual(model.read_bytes(),raw)
    def test_case_survives_source_removal(self):
        p=self.source/'history';p.write_text('controlled')
        acquire([(self.source,'.ollama')],self.case,'macos',8192)
        p.unlink()
        self.assertTrue(verify_case(self.case)['verified'])
        self.assertEqual(scan(self.case/'evidence')['findings'][0]['observations'][0]['text'],'controlled')
    def test_sidecar_appearance_quarantines_capture(self):
        source=self.source/'Library/Application Support/Ollama/db.sqlite';source.parent.mkdir(parents=True)
        source.write_bytes(b'placeholder')
        original=read_stable;calls=0
        def change(path,limit):
            nonlocal calls
            data=original(path,limit);calls+=1
            if calls==2:Path(str(source)+'-wal').write_bytes(b'new WAL')
            return data
        with patch('llm_forensics.acquisition.read_stable',side_effect=change):m=acquire([(self.source,None)],self.case,'macos',8192)
        self.assertEqual(m['files'][0]['status'],'quarantined')
        self.assertIn('sidecar_membership_changed',json.dumps(m['issues']))

    def test_verification_rejects_missing_capture_directory(self):
        acquire([(self.source,None)],self.case,'macos',8192)
        (self.case/'evidence').rmdir()
        self.assertFalse(verify_case(self.case)['verified'])

    def test_verification_reports_enumeration_denial(self):
        acquire([(self.source,None)],self.case,'macos',8192)
        def denied(path,followlinks,onerror):
            onerror(PermissionError(13,'controlled denial',str(path)))
            return iter(())
        with patch('llm_forensics.acquisition.os.walk',side_effect=denied):
            result=verify_case(self.case)
        self.assertFalse(result['verified'])
        self.assertEqual(result['files'][0]['status'],'unreadable')
