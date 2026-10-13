import hashlib,sqlite3,tempfile,unittest
from pathlib import Path
from llm_forensics.scanner import scan

class DesktopTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.path=self.root/'Library/Application Support/Ollama/db.sqlite';self.path.parent.mkdir(parents=True)
        self.c=sqlite3.connect(self.path)
        self.c.executescript('CREATE TABLE chats(id TEXT PRIMARY KEY,title TEXT); CREATE TABLE messages(id INTEGER PRIMARY KEY,chat_id TEXT,role TEXT,content TEXT,created_at TEXT,model_name TEXT); INSERT INTO chats VALUES("chat-1","test");')
    def tearDown(self):self.c.close();self.temp.cleanup()
    def test_messages_and_explicit_timezone(self):
        self.c.execute('INSERT INTO messages VALUES(1,?,?,?,?,?)',('chat-1','user','test prompt','2026-09-28 16:00:00+05:30',None));self.c.commit()
        f=scan(self.root,source_os='macos')['findings'][0]
        self.assertEqual(f['observations'][0]['text'],'test prompt')
        self.assertEqual(f['observations'][0]['timestamp'],'2026-09-28T10:30:00+00:00')
        self.assertEqual(f['observations'][0]['record_locator'],'messages.id=1')
    def test_wal_records_and_source_preservation(self):
        self.c.execute('PRAGMA journal_mode=WAL');self.c.execute('PRAGMA wal_autocheckpoint=0')
        self.c.execute('INSERT INTO messages VALUES(1,?,?,?,?,?)',('chat-1','assistant','from WAL','2026-09-28 16:00:00','demo'));self.c.commit()
        paths=[self.path,Path(str(self.path)+'-wal')]
        before=[hashlib.sha256(p.read_bytes()).hexdigest() for p in paths]
        f=scan(self.root,source_os='macos')['findings'][0]
        self.assertEqual(f['observations'][0]['text'],'from WAL')
        self.assertIsNone(f['observations'][0]['timestamp'])
        self.assertEqual(len(f['acquisition_files']),2)
        self.assertEqual(before,[hashlib.sha256(p.read_bytes()).hexdigest() for p in paths])
    def test_empty_reply_retained_as_empty(self):
        self.c.execute('INSERT INTO messages VALUES(1,?,?,?,?,?)',('chat-1','assistant','','invalid','demo'));self.c.commit()
        record=scan(self.root,source_os='macos')['findings'][0]['observations'][0]
        self.assertEqual(record['content_state'],'empty');self.assertIsNone(record['timestamp'])
    def test_size_limit(self):
        self.c.commit();f=scan(self.root,max_bytes=1,source_os='macos')['findings'][0]
        self.assertEqual(f['status'],'size_limit')
    def test_unknown_schema(self):
        self.c.execute('DROP TABLE messages');self.c.commit()
        self.assertEqual(scan(self.root,source_os='macos')['findings'][0]['status'],'unsupported_schema')
    def test_recovery_schema_skip_is_explicit(self):
        self.c.commit()
        finding=scan(self.root,source_os='macos',recover_deleted=True)['findings'][0]
        self.assertEqual(finding['recovery']['status'],'skipped')
        self.assertIn('schema',finding['recovery']['reason'])
    def test_recovery_wal_skip_preserves_current_messages(self):
        self.c.execute('PRAGMA journal_mode=WAL')
        self.c.execute('INSERT INTO messages VALUES(1,?,?,?,?,?)',('chat-1','user','WAL content','2026-09-28 16:00:00+05:30',None));self.c.commit()
        finding=scan(self.root,source_os='macos',recover_deleted=True)['findings'][0]
        self.assertIn('Nonempty WAL',finding['recovery']['reason'])
        self.assertEqual(finding['observations'][0]['text'],'WAL content')
    def test_recovery_deleted_records_and_default_opt_out(self):
        self.c.execute('DROP TABLE messages')
        self.c.execute('PRAGMA secure_delete=OFF')
        self.c.execute('CREATE TABLE messages(id INTEGER PRIMARY KEY, chat_id TEXT, role TEXT, content TEXT, thinking TEXT, stream BOOLEAN, model_name TEXT, model_cloud BOOLEAN, model_ollama_host BOOLEAN, created_at TIMESTAMP, updated_at TIMESTAMP, thinking_time_start TIMESTAMP, thinking_time_end TIMESTAMP, tool_result TEXT)')
        for i in range(40):
            self.c.execute('INSERT INTO messages VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(i+1,'12345678-1234-1234-1234-123456789abc','user',str(i)+'x'*500,'',0,None,0,0,'2026-09-28 12:00:00+05:30','2026-09-28 12:00:00+05:30',None,None,None))
        self.c.commit();self.c.execute('DELETE FROM messages');self.c.commit()
        original=self.path.read_bytes()
        self.assertNotIn('recovery',scan(self.root,source_os='macos')['findings'][0])
        f=scan(self.root,source_os='macos',recover_deleted=True)['findings'][0]
        self.assertEqual(f['observations'],[])
        self.assertEqual(f['recovery']['status'],'completed')
        self.assertTrue(f['recovery']['records'])
        self.assertTrue(all(r['current_record_comparison']=='not found in current rows' for r in f['recovery']['records']))
        self.assertEqual(original,self.path.read_bytes())
