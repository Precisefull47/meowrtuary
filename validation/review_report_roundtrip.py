"""Exercise the released CLI's large-report scan, comparison and scoring paths."""
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

command=sys.argv[1:]
if not command:raise SystemExit('Supply CLI executable or Python launcher arguments')
with tempfile.TemporaryDirectory(prefix='llmf-roundtrip-') as d:
    root=Path(d).resolve();source=root/'source/Library/Application Support/Ollama/db.sqlite';source.parent.mkdir(parents=True)
    db=sqlite3.connect(source)
    db.executescript("CREATE TABLE chats(id TEXT,title TEXT);INSERT INTO chats VALUES('a','synthetic');CREATE TABLE messages(id INTEGER,chat_id TEXT,role TEXT,content TEXT,created_at TEXT);")
    db.executemany('INSERT INTO messages VALUES(?,?,?,?,?)',((i,'a','user',f'SYNTHETIC_{i}','2026-09-30T00:00:00Z') for i in range(10000)));db.commit();db.close()
    expected=root/'expected.json';expected.write_text(json.dumps({'schema_version':1,'scope':{'runner':'ollama','artifact_type':'desktop_sqlite','record_kind':'current'},'records':[{'role':'user','text':f'SYNTHETIC_{i}'} for i in range(10000)]}))
    def run(*args):subprocess.run(command+list(map(str,args)),check=True,capture_output=True,text=True,timeout=90)
    case=root/'case'
    run(source,'--source-os','macos','--timeline','--output',case)
    run('--compare',case,case,'--output',root/'comparison')
    run('--score-records',expected,case,'--output',root/'score')
    run('--verify-package',case)
    comparison=json.loads((root/'comparison/comparison.json').read_text());score=json.loads((root/'score/accuracy.json').read_text())
    assert comparison['summary']=={'unchanged':1} and score['exact_match'] and score['matched_records']==10000
    result={'passed':True,'records':10000,'report_bytes':(case/'report.json').stat().st_size,'comparison':comparison['summary'],'matched_records':score['matched_records'],'whole_case_verified':True,'scope':'Synthetic packaged CLI round trip; no real user data'}
print(json.dumps(result,indent=2))
