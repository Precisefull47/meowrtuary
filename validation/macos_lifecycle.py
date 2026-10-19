"""Reproducible storage-layer deletion tests; not GUI/version certification."""
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from llm_forensics.sqlite_carve import carve_freelist

SCHEMA='CREATE TABLE messages(id INTEGER PRIMARY KEY,chat_id TEXT,role TEXT,content TEXT,thinking TEXT,stream BOOLEAN,model_name TEXT,model_cloud BOOLEAN,model_ollama_host BOOLEAN,created_at TIMESTAMP,updated_at TIMESTAMP,thinking_time_start TIMESTAMP,thinking_time_end TIMESTAMP,tool_result TEXT)'
MARKER='LLMF_LIFECYCLE_CONTROLLED_20260929'


def run():
    outcomes=[]
    for cleanup in ('delete_only','secure_delete','vacuum'):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'db.sqlite';db=sqlite3.connect(path)
            db.execute('PRAGMA secure_delete='+('ON' if cleanup=='secure_delete' else 'OFF'))
            db.execute(SCHEMA)
            for i in range(40):db.execute('INSERT INTO messages VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(i+1,'12345678-1234-1234-1234-123456789abc','user',f'{MARKER}_{i} '+'x'*500,'',0,'synthetic',0,0,'2026-09-29T05:00:00Z','2026-09-29T05:00:00Z',None,None,None))
            db.commit();db.close()
            # Reopen the real SQLite file to verify durable current rows.
            db=sqlite3.connect(path);before=db.execute('SELECT count(*) FROM messages').fetchone()[0]
            db.execute('PRAGMA secure_delete='+('ON' if cleanup=='secure_delete' else 'OFF'))
            db.execute('DELETE FROM messages');db.commit()
            if cleanup=='vacuum':db.execute('VACUUM')
            db.close();data=path.read_bytes();rows=carve_freelist(data)
            outcomes.append({'cleanup':cleanup,'rows_after_reopen':before,'carved_records':len(rows),'plaintext_marker_survived':MARKER.encode() in data,'sha256':hashlib.sha256(data).hexdigest()})
    assert outcomes[0]['carved_records']>0 and outcomes[0]['plaintext_marker_survived']
    assert outcomes[1]['carved_records']==0 and not outcomes[1]['plaintext_marker_survived']
    assert outcomes[2]['carved_records']==0 and not outcomes[2]['plaintext_marker_survived']
    return {'passed':True,'test_type':'synthetic SQLite storage lifecycle','outcomes':outcomes,
        'limitations':'No runner uninstall, raw disk, snapshots, SSD TRIM or secure-erase guarantees. Actual app settings may differ. The controls show why recovery is conditional.'}


if __name__=='__main__':print(json.dumps(run(),indent=2))
