"""Read observed Ollama desktop schema using a disposable DB/WAL copy."""
import hashlib,json,sqlite3,tempfile,stat,time
from pathlib import Path
from .acquisition import read_stable, unlinked
from datetime import datetime,timezone


def read_desktop(path,max_bytes,version,recover_deleted=False):
    unlinked(path)
    finding={'runner':'ollama','artifact_type':'desktop_sqlite','source_path':str(path),'parser_version':version,
      'validation':'Observed Ollama desktop schema; validated on a macOS capture, not all releases.',
      'status':'parsed','observations':[],'limitations':['DB and WAL are copied before querying; a live multi-file capture is not atomic.',
      'Logical current rows only; no deleted-row carving. Empty replies may represent unfinished or failed generation.',
      'Stored model names and content do not independently prove authorship.'],
      'schema_adapter':'ollama-desktop-chats-messages','source_changed_during_read':False,'acquisition_files':[]}
    if recover_deleted:
        finding['recovery']={'status':'skipped','reason':'Database was not successfully parsed','records':[]}
    sidecars=lambda:{suffix for suffix in ('-wal','-shm','-journal') if Path(str(path)+suffix).exists()}
    initial_sidecars=sidecars()
    journal=Path(str(path)+'-journal')
    if journal.exists() and journal.stat().st_size:
        finding['status']='unsupported_snapshot'
        finding['limitations'].append('Nonempty rollback journal; acquire a quiescent consistent database before parsing.')
        return finding
    with tempfile.TemporaryDirectory(prefix='llm-db-') as directory:
        copied=[]
        for suffix in ('','-wal'):
            source=Path(str(path)+suffix)
            try: info=source.lstat()
            except FileNotFoundError:
                if suffix:continue
                raise
            if not stat.S_ISREG(info.st_mode) or source.is_symlink() or getattr(info,'st_file_attributes',0)&0x400:
                raise ValueError('Database or WAL is not a regular unlinked file')
            if info.st_size>max_bytes:
                finding.update(status='size_limit',size_bytes=path.stat().st_size,sha256=None,hash_scope='not hashed')
                finding['limitations'].append('Database or WAL exceeds configured size limit.')
                return finding
            data,info=read_stable(source,max_bytes)
            if len(data)>max_bytes:raise ValueError('Database grew beyond read limit')
            digest=hashlib.sha256(data).hexdigest()
            (Path(directory)/('db.sqlite'+suffix)).write_bytes(data)
            finding['acquisition_files'].append({'source_path':str(source),'sha256':digest,'size_bytes':len(data)})
            copied.append((source,digest))
            if not suffix:
                finding.update(size_bytes=len(data),sha256=digest,hash_scope='main database only; WAL hash recorded separately',filesystem_mtime_utc=datetime.fromtimestamp(info.st_mtime,timezone.utc).isoformat())
        for source,digest in copied:
            check,_=read_stable(source,max_bytes)
            if hashlib.sha256(check).hexdigest()!=digest:finding['source_changed_during_read']=True
        if sidecars()!=initial_sidecars:finding['source_changed_during_read']=True
        if finding['source_changed_during_read']:
            finding['status']='unstable_capture'
            finding['limitations'].append('Source changed during copying; reacquire before interpreting messages.')
            return finding
        connection=None
        try:
            connection=sqlite3.connect((Path(directory)/'db.sqlite').as_uri()+'?mode=ro',uri=True)
            connection.execute('PRAGMA query_only=ON')
            connection.execute('PRAGMA trusted_schema=OFF')
            deadline=time.monotonic()+5
            connection.set_progress_handler(lambda:int(time.monotonic()>deadline),1000)
            check=connection.execute('PRAGMA quick_check(1)').fetchone()
            if not check or check[0]!='ok':
                finding['status']='invalid_database';finding['limitations'].append('SQLite integrity check failed on disposable copy.');return finding
            finding['sqlite_integrity_check']='quick_check ok on disposable copy'
            connection.row_factory=sqlite3.Row
            ordered_columns=[row[1] for row in connection.execute('PRAGMA table_info(messages)')]
            columns=set(ordered_columns)
            chat_columns={row[1] for row in connection.execute('PRAGMA table_info(chats)')}
            if not {'id','chat_id','role','content','created_at'}<=columns or not {'id','title'}<=chat_columns:
                finding['status']='unsupported_schema';return finding
            optional=[x for x in ('model_name','thinking','updated_at') if x in columns]
            select='m.id,m.chat_id,m.role,m.content,m.created_at,c.title'+''.join(',m.'+x for x in optional)
            rows=connection.execute('SELECT '+select+' FROM messages m LEFT JOIN chats c ON c.id=m.chat_id ORDER BY m.id LIMIT 10001').fetchall()
            if len(rows)>10000:
                finding['status']='partial';finding['limitations'].append('Message limit reached: first 10000 rows only.')
            for row in rows[:10000]:
                if any(isinstance(row[k],bytes) for k in row.keys()) or row['role'] not in ('user','assistant','system','tool') or not isinstance(row['content'],str) or any(row[k] is not None and not isinstance(row[k],str) for k in ('title',*optional)):
                    finding.setdefault('unparsed_records',[]).append({'record_locator':'messages row','reason':'Unexpected value type or role in message columns'})
                    finding['status']='partial'
                    continue
                raw=row['created_at']; timestamp=None
                if isinstance(raw,str):
                    try:
                        parsed=datetime.fromisoformat(raw.replace('Z','+00:00'))
                        if parsed.tzinfo:timestamp=parsed.astimezone(timezone.utc).isoformat()
                    except (ValueError,OverflowError):pass
                record={'record_locator':f"messages.id={row['id']}",'message_id':row['id'],'chat_id':row['chat_id'],'chat_title':row['title'],
                        'role':row['role'],'text':row['content'],'timestamp_raw':raw,'timestamp':timestamp,
                        'timestamp_basis':'stored created_at with explicit offset' if timestamp else 'raw created_at; timezone not inferred',
                        'content_state':'present' if row['content'] else 'empty'}
                for field in optional:record[field]=row[field]
                finding['observations'].append(record)
            if recover_deleted:
                from .sqlite_carve import FIELDS, carve_freelist
                recovery=finding['recovery']
                finding['limitations'][1]='Current rows and experimental freelist residue are reported separately. Residue may be superseded rather than deleted.'
                if any(x['source_path'].endswith('-wal') and x['size_bytes'] for x in finding['acquisition_files']):
                    recovery['reason']='Nonempty WAL: freelist recovery skipped; current messages still parsed.'
                elif tuple(ordered_columns)!=FIELDS:
                    recovery['reason']='Unsupported column order or schema for freelist recovery.'
                else:
                    try:
                        candidates=carve_freelist((Path(directory)/'db.sqlite').read_bytes())
                        fields=('chat_id','role','text','timestamp_raw','updated_at','model_name','thinking')
                        key=lambda r:tuple(r.get(f) for f in fields)
                        active={key(r) for r in finding['observations']}
                        grouped={}
                        for candidate in candidates:
                            k=key(candidate)
                            if k not in grouped:
                                grouped[k]=dict(candidate,locations=[],current_record_comparison='matches current row' if k in active else ('not found in first 10000 current rows' if len(rows)>10000 else 'not found in current rows'))
                            grouped[k]['locations'].append({f:candidate[f] for f in ('byte_offset','byte_length','page_number')})
                        recovery.update(status='completed',reason=None,candidate_count=len(candidates),records=sorted(grouped.values(),key=lambda r:r['timestamp_raw']),limitations='Experimental intact-record candidates, not confirmed deletions. Row IDs and deletion times are not recovered. Ordering uses stored creation times; mixed timezone offsets require normalized timestamps. Fragmented records are not reconstructed.')
                    except ValueError as exc:
                        recovery.update(status='unsupported',reason=str(exc))
        except sqlite3.Error as exc:
            finding['status']='parse_error';finding['limitations'].append(f'SQLite error: {exc}')
        finally:
            if connection is not None:connection.close()
    return finding
