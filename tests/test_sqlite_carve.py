import sqlite3
import tempfile
import unittest
from pathlib import Path
from llm_forensics.sqlite_carve import carve_freelist


class CarveTests(unittest.TestCase):
    def test_deleted_intact_records_and_source_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'db.sqlite'
            db = sqlite3.connect(path)
            db.execute('PRAGMA secure_delete=OFF')
            db.execute('CREATE TABLE messages(id INTEGER PRIMARY KEY, chat_id TEXT, role TEXT, content TEXT, thinking TEXT, stream BOOLEAN, model_name TEXT, model_cloud BOOLEAN, model_ollama_host BOOLEAN, created_at TIMESTAMP, updated_at TIMESTAMP, thinking_time_start TIMESTAMP, thinking_time_end TIMESTAMP, tool_result TEXT)')
            for i in range(40):
                db.execute('INSERT INTO messages VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)', (i+1,'12345678-1234-1234-1234-123456789abc','user',f'message {i}: '+ 'x'*500,'',0,None,0,0,'2026-09-28 12:00:00+05:30','2026-09-28 12:00:00+05:30',None,None,None))
            db.commit()
            db.execute('DELETE FROM messages')
            db.commit()
            db.close()
            before = path.read_bytes()
            rows = carve_freelist(before)
            self.assertTrue(rows)
            self.assertTrue(all(r['chat_id']=='12345678-1234-1234-1234-123456789abc' for r in rows))
            self.assertTrue(all(r['timestamp']=='2026-09-28T06:30:00+00:00' for r in rows))
            self.assertEqual(before,path.read_bytes())
            bad = bytearray(before)
            bad[32:36]=(999999).to_bytes(4,'big')
            with self.assertRaises(ValueError): carve_freelist(bad)
            bad = bytearray(before)
            bad[56:60]=(2).to_bytes(4,'big')
            with self.assertRaises(ValueError): carve_freelist(bad)

    def test_invalid_input(self):
        with self.assertRaises(ValueError): carve_freelist(b'not sqlite')
