"""Copy known report outputs without changing or relocating their source case."""
import hashlib
import json
from pathlib import Path
from .acquisition import read_stable
from .case_package import seal_case, verify_package
from .output_location import create_output, check_storage

REPORT_NAMES = ('report.html','report.json','conversations.json','timeline.json','timeline.csv',
                'comparison.html','comparison.json','recovered-residue.json','decoded-sessions.json',
                'accuracy.json','validation-results.json')


def available_reports(case):
    case=Path(case)
    return [case/name for name in REPORT_NAMES if (case/name).is_file() and not (case/name).is_symlink()]


def export_reports(case, output):
    case=Path(case).absolute();output=Path(output).resolve()
    if output==case.resolve() or case.resolve() in output.parents:
        raise ValueError('Report export must be outside the source case')
    sealed=(case/'case-integrity.json').exists()
    before=verify_package(case) if sealed else None
    if before and not before['verified']:raise ValueError('Source case integrity failed; export refused')
    paths=available_reports(case)
    if not paths:raise ValueError('No supported reports found')
    # Bound memory and reject source changes before creating output.
    copies=[];total=0
    for path in paths:
        data,_=read_stable(path,64*1024*1024);total+=len(data)
        if total>128*1024*1024:raise ValueError('Report export exceeds 128 MiB safety limit')
        copies.append((path,data))
    create_output(output)
    entries=[]
    for path,data in copies:
        check_storage()
        with (output/path.name).open('xb') as stream:stream.write(data)
        entries.append({'name':path.name,'source_path':str(path),'sha256':hashlib.sha256(data).hexdigest()})
    for path,data in copies:
        current,_=read_stable(path,64*1024*1024)
        if current!=data:raise ValueError('Source report changed during export; retain partial output')
    if sealed:
        after=verify_package(case)
        if not after['verified'] or after['manifest_sha256']!=before['manifest_sha256']:
            raise ValueError('Source case changed during export; retain partial output')
    (output/'report-export.json').write_text(json.dumps({'schema_version':1,'source_case':str(case),
        'source_integrity_verified':sealed,'source_manifest_sha256':before['manifest_sha256'] if sealed else None,
        'files':entries,'limitations':'Report copies only, not an acquired case. Original evidence references are unchanged and refer to the source case. Keep the source case for evidence access. Hashes are unsigned.'},indent=2,ensure_ascii=True))
    for entry in entries:
        data,_=read_stable(output/entry['name'],64*1024*1024)
        if hashlib.sha256(data).hexdigest()!=entry['sha256']:raise ValueError('Export copy hash mismatch')
    if not (output/'report.json').exists() and not (output/'report.html').exists():
        return {'verified':True,'reports':len(entries),'output':str(output),'verification':'Copy hashes; not a case seal'}
    seal_case(output)
    if not verify_package(output)['verified']:raise ValueError('Export integrity verification failed')
    return {'verified':True,'reports':len(entries),'output':str(output)}
