from .output_location import create_output, check_storage
"""Unsigned integrity manifests and portable archives for complete case outputs."""
import hashlib
import io
import json
from .structured import loads as bounded_json_loads
import os
from pathlib import Path
import tarfile
import tempfile
import re
from datetime import datetime, timezone
from .acquisition import read_stable, unlinked, verify_case

MANIFEST='case-integrity.json'
MAX_FILE=128*1024*1024
MAX_TOTAL=1024*1024*1024


def inventory(case):
    case=unlinked(Path(case).absolute())
    if not case.is_dir():raise ValueError('Case must be a directory')
    files=[];directories=[]
    def fail(exc):raise exc
    for directory,dirs,names in os.walk(case,followlinks=False,onerror=fail):
        for name in sorted(dirs+names):
            p=unlinked(Path(directory)/name);rel=p.relative_to(case).as_posix()
            if p.is_dir():directories.append(rel)
            elif p.is_file():
                if rel!=MANIFEST:files.append(rel)
            else:raise ValueError('Case contains a non-regular file')
            if len(files)+len(directories)>20000:raise ValueError('Case entry limit exceeded')
    return case,sorted(files),sorted(directories)


def seal_case(case):
    case,files,dirs=inventory(case)
    if not (case/'report.json').is_file() and not (case/'report.html').is_file():raise ValueError('A case report is required before sealing')
    if (case/MANIFEST).exists():raise FileExistsError('Case already sealed; use --verify-package')
    if (case/'acquisition-manifest.json').exists() and not verify_case(case)['verified']:raise ValueError('Raw capture failed integrity verification; refusing to seal')
    entries=[];total=0
    for rel in files:
        data,_=read_stable(case/rel,MAX_FILE);total+=len(data)
        if total>MAX_TOTAL:raise ValueError('Case package exceeds 1 GiB limit')
        entries.append({'path':rel,'size_bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
    if inventory(case)[1:]!=(files,dirs):raise ValueError('Case membership changed during sealing')
    result={'schema_version':1,'created_utc':datetime.now(timezone.utc).isoformat(),'files':entries,'directories':dirs,
        'limitations':'Unsigned integrity snapshot, not authenticity or chain-of-custody certification. Includes raw evidence and generated reports; excludes this manifest itself.'}
    target=case/MANIFEST
    fd,temporary=tempfile.mkstemp(prefix='.integrity-',suffix='.pending',dir=case)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as stream:
            json.dump(result,stream,indent=2);stream.flush();os.fsync(stream.fileno())
        # Atomic no-overwrite publication; destination must support hard links.
        os.link(temporary,target)
    finally:
        Path(temporary).unlink(missing_ok=True)
    verified=verify_package(case)
    if not verified['verified']:raise ValueError('Case changed while sealing; integrity check failed')
    return verified


def verify_package(case):
    case,files,dirs=inventory(case);data,_=read_stable(case/MANIFEST,16*1024*1024);manifest=bounded_json_loads(data);manifest_hash=hashlib.sha256(data).hexdigest()
    if not isinstance(manifest,dict) or manifest.get('schema_version')!=1 or not isinstance(manifest.get('files'),list) or len(manifest['files'])>20000:raise ValueError('Invalid case integrity manifest')
    if not manifest['files']:raise ValueError('Empty integrity manifest')
    directories=manifest.get('directories')
    if not isinstance(directories,list) or any(not isinstance(d,str) or not d or Path(d).is_absolute() or '..' in Path(d).parts or Path(d).as_posix()!=d for d in directories):raise ValueError('Invalid directory list')
    if len(directories)!=len(set(directories)):raise ValueError('Duplicate directories')
    listed={};results=[];total=0
    for entry in manifest['files']:
        if not isinstance(entry,dict) or not isinstance(entry.get('path'),str):raise ValueError('Invalid file entry')
        rel=entry['path'];p=Path(rel)
        if not rel or p.is_absolute() or '..' in p.parts or p.as_posix()!=rel or rel in listed or rel==MANIFEST:raise ValueError('Unsafe or duplicate case entry')
        if type(entry.get('size_bytes')) is not int or entry['size_bytes']<0 or not isinstance(entry.get('sha256'),str) or not re.fullmatch(r'[0-9a-f]{64}',entry['sha256']):raise ValueError('Invalid hash entry')
        listed[rel]=entry
        try:
            data,_=read_stable(case/p,MAX_FILE);total+=len(data)
            if total>MAX_TOTAL:raise ValueError('Case package exceeds 1 GiB limit')
            status='verified' if len(data)==entry['size_bytes'] and hashlib.sha256(data).hexdigest()==entry['sha256'] else 'mismatch'
        except OSError:status='missing_or_unreadable'
        results.append({'path':rel,'status':status})
    results.extend({'path':p,'status':'unlisted'} for p in sorted(set(files)-set(listed)))
    if dirs!=manifest.get('directories'):results.append({'path':'[directory membership]','status':'mismatch'})
    return {'verified':all(r['status']=='verified' for r in results),'files':results,'manifest_sha256':manifest_hash,
        'limitations':'Integrity against an unsigned manifest only; no authenticity guarantee.'}


def bundle_case(case,output):
    case=Path(case).absolute();output=Path(output).resolve()
    if output==case.resolve() or case.resolve() in output.parents:raise ValueError('Bundle output must be outside case')
    verified=verify_package(case)
    if not verified['verified']:raise ValueError('Case integrity failed; refusing to bundle')
    raw,_=read_stable(case/MANIFEST,16*1024*1024);manifest=bounded_json_loads(raw)
    if hashlib.sha256(raw).hexdigest()!=verified['manifest_sha256']:raise ValueError('Manifest changed')
    create_output(output);partial=output/'case.tar.gz.partial'
    with tarfile.open(partial,'w:gz') as tar:
        for rel in ['case']+['case/'+d for d in manifest['directories']]:
            info=tarfile.TarInfo(rel);info.type=tarfile.DIRTYPE;info.mode=0o700;tar.addfile(info)
        for entry in manifest['files']+[{'path':MANIFEST,'size_bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}]:
            data,_=read_stable(case/entry['path'],MAX_FILE)
            if len(data)!=entry['size_bytes'] or hashlib.sha256(data).hexdigest()!=entry['sha256']:raise ValueError('Case changed during bundle creation')
            info=tarfile.TarInfo('case/'+entry['path']);info.size=len(data);info.mode=0o600;tar.addfile(info,io.BytesIO(data))
    final=verify_package(case)
    if not final['verified'] or final['manifest_sha256']!=verified['manifest_sha256']:raise ValueError('Case changed during bundle creation')
    target=output/'case.tar.gz';partial.rename(target);target.chmod(0o600)
    h=hashlib.sha256()
    with target.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):h.update(block)
    (output/'case.tar.gz.sha256').write_text(h.hexdigest()+'  case.tar.gz\n')
    return {'archive':str(target),'sha256':h.hexdigest(),'contains_sensitive_evidence':True}
