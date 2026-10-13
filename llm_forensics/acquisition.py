from .output_location import create_output, check_storage
"""Bounded selective acquisition. Raw copies are never opened by SQLite here.

Stable two-read captures are best effort, not an atomic snapshot or write blocker.
"""
import hashlib
import json
from .structured import loads as bounded_json_loads
import os
import shutil
import errno
import re
import sys
from pathlib import Path
import stat
from datetime import datetime,timezone
from .discovery import match_rule
from .traversal import Budget, walk, TraversalLimit


def now():return datetime.now(timezone.utc).isoformat()


def unlinked(path):
    path=Path(path).absolute()
    # macOS ships these fixed root aliases. Resolve only the expected OS alias;
    # user-controlled links elsewhere still fail component validation.
    if sys.platform=='darwin' and len(path.parts)>1 and path.parts[1] in {'var','tmp','etc'}:
        alias=Path('/')/path.parts[1]
        expected=Path('/private')/path.parts[1]
        if alias.is_symlink() and (alias.parent/alias.readlink())==expected:
            path=expected.joinpath(*path.parts[2:])
    for component in (path,*path.parents):
        info=component.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:
            raise ValueError('Symlink or reparse component is not permitted')
    return path


def read_stable(path,limit,prefix=False):
    path=unlinked(path)
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):raise ValueError('Not a regular file')
        if before.st_size>limit and not prefix:raise ValueError('size_limit')
        data=stream.read(limit if prefix else limit+1);after=os.fstat(stream.fileno())
        current=path.stat()
        keys=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        if len(data)>limit or keys(before)!=keys(after) or keys(after)!=keys(current):raise ValueError('source_changed')
    return data,before


def read_model_header(path,limit):
    if limit<24:raise ValueError("Insufficient capture budget for model header")
    return read_stable(path,24,prefix=True)


def acquire(scopes,case,system,max_bytes,total_limit=512*1024*1024,max_files=10000,optional_sources=(),traversal_budget=None):
    """Scopes are (explicit source, optional conventional root name)."""
    case=Path(case).absolute()
    for source,alias in scopes:
        resolved=Path(source).resolve()
        if case==resolved or resolved in case.parents:raise ValueError('Case output must be outside all source scopes')
        if alias not in (None,'.ollama','.lmstudio'):raise ValueError('Invalid scope alias')
    create_output(case)
    evidence=case/'evidence';evidence.mkdir(mode=0o700)
    quarantine=case/'quarantine';quarantine.mkdir(mode=0o700)
    manifest={'schema_version':1,'started_utc':now(),'source_os':system,'scopes':[], 'files':[],'issues':[],
        'limits':{'max_file_bytes':max_bytes,'max_total_bytes':total_limit,'max_files':max_files},
        'limitations':['Selective capture of supported path candidates and small Ollama blobs, not a full disk image.',
            'Two matching reads and stable sidecar membership do not prove an atomic live snapshot. Close the runner or acquire offline for stronger consistency.',
            'No write blocker; reading may change access times. Hashes detect later change, not authenticity or authorship.',
            'GGUF files are captured as 24-byte headers only; model tensors are not copied or fully hashed.',
            'Extended attributes, ACLs and original creation times are not preserved; original mtime is recorded.'],
        'status':'in_progress'}
    optional={str(Path(p).absolute()) for p in optional_sources}
    used=0;seen=set();count=0
    budget=traversal_budget if traversal_budget is not None else Budget()
    def persist():
        temporary=case/'acquisition-manifest.json.pending'
        with temporary.open('w',encoding='utf-8') as stream:
            json.dump(manifest,stream,indent=2,ensure_ascii=True);stream.flush();os.fsync(stream.fileno())
        temporary.replace(case/'acquisition-manifest.json')
    persist()
    try:
        for index,(source,alias) in enumerate(scopes,1):
            source=Path(source).absolute();scope={'source_path':str(source),'alias':alias,'status':'pending'};manifest['scopes'].append(scope)
            try:
                unlinked(source)
                isfile=source.is_file()
                if not isfile and not source.is_dir():raise ValueError('Not a file or directory')
                # Retain absolute path components, or an operator-declared conventional home.
                relative_base=Path(alias) if alias else Path(*source.parts[1:])
                prefix=Path(f'scope-{index:03d}')/relative_base
                base=source.parent if isfile else source
                def walk_error(exc):manifest['issues'].append({'source_path':str(exc.filename),'status':'inaccessible','detail':str(exc)})
                limited=False
                def traversal_limit(exc):
                    nonlocal limited
                    limited=True
                    manifest['issues'].append({'source_path':str(source),'status':'traversal_limit','detail':str(exc)})
                entries=walk(source,budget,walk_error,traversal_limit,isfile)
                for directory,dirs,files in entries:
                    dirs.sort()
                    for name in list(dirs):
                        try:unlinked(Path(directory)/name)
                        except (OSError,ValueError) as exc:
                            dirs.remove(name);manifest['issues'].append({'source_path':str(Path(directory)/name),'status':'skipped_link_or_inaccessible','detail':str(exc)})
                    for name in sorted(files):
                        budget.check()
                        path=Path(directory)/name
                        if str(path) in seen:continue
                        rel=Path(name) if isfile else path.relative_to(source)
                        dest_rel=prefix if isfile else prefix/rel
                        match_path=Path(alias)/rel if alias else path
                        rule=match_rule(match_path,system)
                        small_blob='/models/blobs/sha256-' in str(match_path).replace('\\','/')
                        if not rule and not small_blob:continue
                        if count>=max_files:raise ValueError('File-count limit reached')
                        group=[path]
                        if rule and rule.kind=='desktop_sqlite':
                            group += [Path(str(path)+suffix) for suffix in ('-wal','-shm','-journal') if Path(str(path)+suffix).exists()]
                        originals=[];error=None
                        prefix_only=bool(rule and rule.kind=='gguf_header')
                        reader=read_model_header if prefix_only else read_stable
                        try:
                            if small_blob:
                                header,_=read_model_header(path,min(max_bytes,max(0,total_limit-used)))
                                prefix_only=header.startswith(b'GGUF')
                                reader=read_model_header if prefix_only else read_stable
                            for member in group:
                                if count>=max_files:raise ValueError('File-count limit reached')
                                seen.add(str(member));count+=1
                                data,info=reader(member,min(max_bytes,max(0,total_limit-used)))
                                used+=len(data)
                                suffix=str(member)[len(str(path)):]
                                destination=Path(str(dest_rel)+suffix)
                                entry={'source_path':str(member),'case_path':str(Path('evidence')/destination),
                                    'sha256':hashlib.sha256(data).hexdigest(),'size_bytes':len(data),'source_size_bytes':info.st_size,'capture_mode':'prefix' if prefix_only else 'complete','hash_scope':'first 24 bytes only' if prefix_only else 'complete bytes captured','source_mtime_ns':info.st_mtime_ns,
                                    'source_mtime_utc':datetime.fromtimestamp(info.st_mtime,timezone.utc).isoformat(),'status':'captured'}
                                originals.append((entry,data,info,destination))
                            for entry,data,info,destination in originals:
                                check,check_info=reader(Path(entry['source_path']),max_bytes)
                                if check!=data or (info.st_ino,info.st_dev,info.st_mtime_ns,info.st_ctime_ns)!=(check_info.st_ino,check_info.st_dev,check_info.st_mtime_ns,check_info.st_ctime_ns):raise ValueError('source_changed')
                            if rule and rule.kind=='desktop_sqlite':
                                current=[path]+[Path(str(path)+suffix) for suffix in ('-wal','-shm','-journal') if Path(str(path)+suffix).exists()]
                                if current!=group:raise ValueError('sidecar_membership_changed')
                                if any(e['source_path'].endswith('-journal') and e['size_bytes'] for e,_,_,_ in originals):raise ValueError('nonempty_rollback_journal; quiesce source before analysis')
                        except (OSError,ValueError) as exc:error=str(exc)
                        for entry,data,info,destination in originals:
                            target=(quarantine if error else evidence)/destination
                            check_storage()
                            target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
                            if shutil.disk_usage(case).free<len(data)+1024*1024:
                                raise OSError(errno.ENOSPC,'Insufficient free space; reserving 1 MiB for capture diagnostics')
                            with target.open('xb') as handle:
                                handle.write(data);handle.flush();os.fsync(handle.fileno())
                            target.chmod(0o600);os.utime(target,ns=(info.st_atime_ns,info.st_mtime_ns))
                            if error:entry.update(status='quarantined',case_path=str(Path('quarantine')/destination),reason=error)
                            manifest['files'].append(entry)
                        if error:manifest['issues'].append({'source_path':str(path),'status':'capture_failed','detail':error})
                scope['status']='incomplete' if limited else 'enumerated'
            except TraversalLimit as exc:
                scope.update(status='incomplete',detail=str(exc))
                manifest['issues'].append({'source_path':str(source),'status':'traversal_limit','detail':str(exc)})
            except FileNotFoundError as exc:
                if str(source) in optional:scope['status']='not_found'
                else:
                    scope.update(status='incomplete',detail=str(exc));manifest['issues'].append({'source_path':str(source),'status':'scope_incomplete','detail':str(exc)})
            except (OSError,ValueError) as exc:
                scope.update(status='incomplete',detail=str(exc));manifest['issues'].append({'source_path':str(source),'status':'scope_incomplete','detail':str(exc)})
            persist()
        manifest['traversal']=budget.snapshot()
        manifest.update(status='partial' if manifest['issues'] else 'complete',finished_utc=now(),captured_bytes=used)
    except BaseException:
        manifest.update(status='interrupted',finished_utc=now())
        try:persist()
        except OSError:pass  # Preserve the last atomic manifest if the disk is unavailable.
        raise
    persist()
    return manifest


def verify_case(case):
    case=unlinked(Path(case))
    path=case/'acquisition-manifest.json'
    data,_=read_stable(path,16*1024*1024);manifest=bounded_json_loads(data)
    if not isinstance(manifest,dict) or manifest.get('schema_version')!=1 or not isinstance(manifest.get('files'),list) or len(manifest['files'])>10000:raise ValueError('Unsupported manifest')
    results=[];listed=set()
    for entry in manifest['files']:
        if not isinstance(entry,dict) or not isinstance(entry.get('case_path'),str):raise ValueError('Invalid manifest file entry')
        rel=Path(entry['case_path'])
        if rel.is_absolute() or '..' in rel.parts or not rel.parts or rel.parts[0] not in ('evidence','quarantine'):raise ValueError('Unsafe manifest path')
        if str(rel) in listed:raise ValueError('Duplicate manifest file path')
        listed.add(str(rel))
        if type(entry.get('size_bytes')) is not int or entry['size_bytes']<0 or not isinstance(entry.get('sha256'),str) or not re.fullmatch(r'[0-9a-f]{64}',entry['sha256']):raise ValueError('Invalid manifest hash or size')
        try:
            content,_=read_stable(case/rel,128*1024*1024)
            valid=len(content)==entry['size_bytes'] and hashlib.sha256(content).hexdigest()==entry['sha256']
            results.append({'case_path':str(rel),'status':'verified' if valid else 'mismatch'})
        except (OSError,ValueError) as exc:results.append({'case_path':str(rel),'status':'unreadable','detail':str(exc)})
    def walk_error(exc):
        results.append({'case_path':str(exc.filename),'status':'unreadable','detail':str(exc)})
    visited=0
    for folder in ('evidence','quarantine'):
        try:
            unlinked(case/folder)
            if not (case/folder).is_dir():raise ValueError('Expected capture directory')
        except (OSError,ValueError) as exc:
            results.append({'case_path':folder,'status':'unreadable','detail':str(exc)})
            continue
        for directory,dirs,files in os.walk(case/folder,followlinks=False,onerror=walk_error):
            for name in dirs+files:
                visited+=1
                if visited>20000:raise ValueError('Case verification entry limit exceeded')
                path=Path(directory)/name;relative=str(path.relative_to(case))
                if path.is_symlink() or (not path.is_dir() and (not path.is_file() or relative not in listed)):
                    results.append({'case_path':relative,'status':'unlisted_or_linked'})
                if len(results)>20000:raise ValueError('Case verification file limit exceeded')
    return {'verified':all(r['status']=='verified' for r in results),'files_checked':len(results),'files':results,
        'acquisition_status':manifest.get('status'),'limitations':'Integrity against this manifest only; the manifest is not signed or authenticated. Empty/partial captures do not prove absence.'}
