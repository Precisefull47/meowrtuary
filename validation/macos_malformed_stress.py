"""Deterministic malformed-input checks; no user profiles or runner execution."""
import hashlib
import json
from pathlib import Path
import random
import tempfile
import time
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from llm_forensics.scanner import scan
from llm_forensics import __version__

start=time.monotonic();randomizer=random.Random(120);outcomes={};checks=0
with tempfile.TemporaryDirectory() as d:
    root=Path(d).resolve();p=root/'.lmstudio/conversations/control.json';p.parent.mkdir(parents=True)
    baseline=b'{"messages":[{"role":"user","content":"CONTROLLED"}]}'
    for index in range(200):
        raw=bytearray(baseline)
        for _ in range(1+index%8):
            position=randomizer.randrange(len(raw));raw[position]=randomizer.randrange(256)
        p.write_bytes(raw);expected=hashlib.sha256(raw).hexdigest();result=scan(root)
        assert len(result['findings'])==1
        f=result['findings'][0];outcomes[f['status']]=outcomes.get(f['status'],0)+1
        assert hashlib.sha256(p.read_bytes()).hexdigest()==expected
        json.dumps(result);checks+=1
    # Large observed-schema SQLite input with bounded output.
    import sqlite3
    p.unlink();dbfile=root/'Library/Application Support/Ollama/db.sqlite';dbfile.parent.mkdir(parents=True)
    db=sqlite3.connect(dbfile);db.executescript('CREATE TABLE chats(id TEXT,title TEXT);CREATE TABLE messages(id INTEGER,chat_id TEXT,role TEXT,content TEXT,created_at TEXT);')
    db.executemany('INSERT INTO messages VALUES(?,?,?,?,?)',((i,'control','user','SYNTHETIC_'+str(i),'2026-09-30T00:00:00Z') for i in range(12000)))
    db.commit();db.close();result=scan(root);f=result['findings'][0]
    assert len(f['observations'])<=10000 and f['status']=='partial';checks+=1
print(json.dumps({'tool_version':__version__,'passed':True,'checks':checks,'mutation_seed':120,'mutation_status_counts':outcomes,'large_sqlite_rows':12000,'large_sqlite_extracted':len(f['observations']),'elapsed_seconds':round(time.monotonic()-start,3),'limitations':'Deterministic synthetic robustness controls, not exhaustive fuzzing or real runner-version validation.'},indent=2))
