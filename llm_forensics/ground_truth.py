"""Exact multiset scoring of independently supplied expected extraction records."""
from collections import Counter
import hashlib
import json
from .structured import loads as bounded_json_loads
from .acquisition import read_stable
from .comparison import load_report


def score(expected_path, report_path):
    raw,_=read_stable(expected_path,8*1024*1024);expected=bounded_json_loads(raw)
    if not isinstance(expected,dict) or expected.get('schema_version')!=1:raise ValueError('Expected ground truth schema_version 1')
    scope=expected.get('scope');records=expected.get('records')
    if not isinstance(scope,dict) or not all(isinstance(scope.get(k),str) for k in ('runner','artifact_type','record_kind')) or scope['record_kind'] not in {'current','historical_candidate'}:
        raise ValueError('Ground truth scope requires runner, artifact_type and record_kind')
    if not isinstance(records,list) or len(records)>10000:raise ValueError('Ground truth records must be a list of at most 10000 role/text objects')
    def key(r):
        if not isinstance(r,dict) or not isinstance(r.get('text'),str) or r.get('role') is not None and not isinstance(r['role'],str):raise ValueError('Each scored record needs text and optional string/null role')
        return (r.get('role'),r['text'])
    wanted=Counter(key(r) for r in records);report,reference=load_report(report_path);actual=Counter();sources=[]
    for f in report['findings']:
        if f['runner']!=scope['runner'] or f['artifact_type']!=scope['artifact_type']:continue
        sources.append({'artifact_id':f['id'],'status':f['status']})
        group=f.get('recovery',{}).get('records',[]) if scope['record_kind']=='historical_candidate' else f['observations']
        for r in group:
            if isinstance(r,dict) and isinstance(r.get('text'),str):actual[key(r)]+=1
    matched=sum((wanted&actual).values());missing=wanted-actual;extra=actual-wanted
    def expanded(counter):return [{'role':role,'text':text,'count':count} for (role,text),count in counter.items()]
    return {'scope':scope,'expected_sha256':hashlib.sha256(raw).hexdigest(),'report':reference,'source_artifacts':sources,
        'expected_records':sum(wanted.values()),'extracted_records':sum(actual.values()),'matched_records':matched,
        'missed_records':sum(missing.values()),'unexpected_records':sum(extra.values()),
        'precision':matched/sum(actual.values()) if actual else None,'recall':matched/sum(wanted.values()) if wanted else None,
        'exact_match':wanted==actual,'missing':expanded(missing),'unexpected':expanded(extra),
        'limitations':'Exact role/text counts in the declared scope only. Supply independent expected records made before extraction. Unexpected records are discrepancies, not automatically false positives. No general recovery-rate claim.'}
