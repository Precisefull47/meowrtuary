from .output_location import create_output, check_storage
"""Offline synthetic acceptance kit, runnable from the packaged executable."""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import sqlite3
from . import __version__
from .scanner import scan
from .sqlite_carve import carve_freelist
from .acquisition import acquire, verify_case

SCHEMA = 'CREATE TABLE messages(id INTEGER PRIMARY KEY,chat_id TEXT,role TEXT,content TEXT,thinking TEXT,stream BOOLEAN,model_name TEXT,model_cloud BOOLEAN,model_ollama_host BOOLEAN,created_at TIMESTAMP,updated_at TIMESTAMP,thinking_time_start TIMESTAMP,thinking_time_end TIMESTAMP,tool_result TEXT)'


def metrics(expected, actual):
    expected,actual=Counter(expected),Counter(actual)
    matched=sum((expected & actual).values()); missed=sum((expected-actual).values()); unexpected=sum((actual-expected).values())
    return {'expected':sum(expected.values()),'extracted':sum(actual.values()),'matched':matched,'missed':missed,'unexpected':unexpected,
            'precision':matched/sum(actual.values()) if actual else None,'recall':matched/sum(expected.values()) if expected else None,
            'exact_match':expected==actual}


def run_kit(output):
    output=Path(output).resolve();create_output(output)
    results={'tool_version':__version__,'host':platform.platform(),'machine':platform.machine(),'checked_utc':datetime.now(timezone.utc).isoformat(),
        'test_type':'Synthetic acceptance and storage controls, not real runner execution', 'checks':[],
        'pending':['Real runner conversations, edits and deletion on this host','Second-machine comparison against baseline host','Signing/notarization and clean-machine launch policy'],
        'limitations':'These exact-match metrics apply only to generated fixtures. They are not general forensic accuracy estimates or guarantees of deleted-content recovery.'}
    try:
        evidence=output/'fixtures';evidence.mkdir()
        chat=evidence/'.lmstudio/conversations/control.json';chat.parent.mkdir(parents=True)
        def save(user, replies):
            chat.write_text(json.dumps({'messages':[{'versions':[{'role':'user','content':[{'type':'text','text':user}]}]},
                {'currentlySelected':len(replies)-1,'versions':[{'role':'assistant','steps':[{'content':[{'type':'text','text':v}]}]} for v in replies]}]}))
        for stage,user,replies in [('baseline','KIT_PROMPT',['KIT_REPLY']),('regeneration','KIT_PROMPT',['KIT_REPLY','KIT_REPLY_2']),('edit','KIT_EDIT',['KIT_REPLY','KIT_REPLY_2']),('reopen','KIT_EDIT',['KIT_REPLY','KIT_REPLY_2'])]:
            save(user,replies)
            digest=hashlib.sha256(chat.read_bytes()).hexdigest()
            report=scan(evidence,source_os='macos')
            actual=[r['text'] for f in report['findings'] for r in f['observations']]
            score=metrics([user,*replies],actual)
            results['checks'].append({'name':'lmstudio_'+stage,**score,'source_unchanged':hashlib.sha256(chat.read_bytes()).hexdigest()==digest})
        trash=evidence/'Users/Analyst/.Trash/control.conversation.json';trash.parent.mkdir(parents=True);chat.rename(trash)
        report=scan(evidence,source_os='macos')
        results['checks'].append({'name':'lmstudio_trash_move',**metrics(['KIT_EDIT','KIT_REPLY','KIT_REPLY_2'],[r['text'] for f in report['findings'] for r in f['observations']])})
        # Check non-chat JSON does not create conversation observations.
        trash.unlink();chat.write_text(json.dumps({'description':'KIT_DISTRACTOR','notes':['KIT_PROMPT']}))
        report=scan(evidence,source_os='macos')
        results['checks'].append({'name':'negative_nonconversation',**metrics([],[r.get('text') for f in report['findings'] for r in f['observations']])})
        for cleanup in ('delete_only','secure_delete','vacuum'):
            path=output/(cleanup+'.sqlite');db=sqlite3.connect(path)
            db.execute('PRAGMA secure_delete='+('ON' if cleanup=='secure_delete' else 'OFF'));db.execute(SCHEMA)
            expected=['KIT_STORAGE_'+str(i)+' '+'x'*500 for i in range(40)]
            for i,text in enumerate(expected): db.execute('INSERT INTO messages VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(i+1,'12345678-1234-1234-1234-123456789abc','user',text,'',0,'synthetic',0,0,'2026-09-29T05:00:00Z','2026-09-29T05:00:00Z',None,None,None))
            db.commit();db.close();db=sqlite3.connect(path)
            rows=[r[0] for r in db.execute('SELECT content FROM messages ORDER BY id')]
            results['checks'].append({'name':cleanup+'_durable_reopen',**metrics(expected,rows)})
            db.execute('PRAGMA secure_delete='+('ON' if cleanup=='secure_delete' else 'OFF'));db.execute('DELETE FROM messages');db.commit()
            if cleanup=='vacuum':db.execute('VACUUM')
            db.close();raw=path.read_bytes();recovered=carve_freelist(raw)
            results['checks'].append({'name':cleanup+'_residue',**metrics(expected if cleanup=='delete_only' else [],[r['text'] for r in recovered]),'sha256':hashlib.sha256(raw).hexdigest()})
        source=output/'custom';source.mkdir();(source/'history').write_text('KIT_CAPTURE\n')
        capture=output/'captured';manifest=acquire([(source,'.ollama')],capture,'macos',8192)
        verified=verify_case(capture)['verified'];(capture/manifest['files'][0]['case_path']).write_text('KIT_TAMPER')
        results['checks'].append({'name':'capture_and_tamper','exact_match':verified and not verify_case(capture)['verified']})
        results['passed']=all(r['exact_match'] and r.get('source_unchanged',True) for r in results['checks'])
    except Exception as exc:
        results.update(passed=False,error=f'{type(exc).__name__}: {exc}')
    (output/'validation-results.json').write_text(json.dumps(results,indent=2)+'\n')
    return results
