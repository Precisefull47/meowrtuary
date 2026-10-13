"""Compare bounded reports without interpreting missing artifacts as deletion."""
from collections import Counter, defaultdict
import hashlib
import html
import json
from .structured import loads as bounded_json_loads, REPORT_NODES, REPORT_BYTES
from pathlib import Path
from .assessment import assess
from .acquisition import read_stable


def load_report(path):
    path = Path(path)
    if path.is_dir(): path = path / 'report.json'
    data, _ = read_stable(path, REPORT_BYTES)
    report = bounded_json_loads(data, max_nodes=REPORT_NODES)
    if not isinstance(report, dict) or report.get('tool') != 'Local LLM Forensics' or not isinstance(report.get('findings'), list):
        raise ValueError('Expected a Local LLM Forensics report.json')
    if len(report['findings']) > 10000: raise ValueError('Report artifact limit exceeded')
    for f in report['findings']:
        if not isinstance(f, dict) or not all(isinstance(f.get(k), str) for k in ('runner','artifact_type','source_path','id','status')):
            raise ValueError('Invalid artifact entry')
        if not isinstance(f.get('observations'), list): raise ValueError('Invalid observations')
    # Validate every nested shape consumed by comparison and coverage assessment.
    # A JSON parse alone says nothing about the report's application schema.
    def mapping(value, label):
        if not isinstance(value, dict): raise ValueError('Invalid '+label+': expected object')
        return value
    def objects(value, label):
        if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
            raise ValueError('Invalid '+label+': expected array of objects')
        return value
    def strings(value, fields, label):
        for key in fields:
            if key in value and value[key] is not None and not isinstance(value[key], str):
                raise ValueError('Invalid '+label+'.'+key+': expected text')
    coverage=mapping(report.get('coverage_summary', {}), 'coverage_summary')
    strings(coverage, ('status',), 'coverage_summary')
    objects(coverage.get('gaps', []), 'coverage_summary.gaps')
    acquisition=mapping(report.get('acquisition', {}), 'acquisition')
    strings(acquisition, ('status',), 'acquisition')
    for name, values in (('issues', report.get('issues', [])),
                         ('locations', report.get('locations', [])),
                         ('acquisition.scopes', acquisition.get('scopes', []))):
        for item in objects(values, name):
            strings(item, ('path','source_path','status','detail'), name)
    for finding in report['findings']:
        strings(finding, ('original_source_path','evidence_relative_path','sha256','hash_scope','schema_adapter'), 'artifact')
        objects(finding['observations'], 'observations')
        recovery=mapping(finding.get('recovery', {}), 'recovery')
        strings(recovery, ('status','reason'), 'recovery')
        objects(recovery.get('records', []), 'recovery.records')
        for item in objects(finding.get('acquisition_files', []), 'acquisition_files'):
            strings(item, ('source_path','sha256'), 'acquisition_files')
            if not isinstance(item.get('source_path'), str) or not isinstance(item.get('sha256'), str) or type(item.get('size_bytes')) is not int or item['size_bytes']<0:
                raise ValueError('Invalid acquisition file identity')
    return report, {'report_path': str(path.absolute()), 'sha256': hashlib.sha256(data).hexdigest()}


def records(finding, historical=False):
    # Preserve duplicates; locator changes alone must not look like new content.
    result = Counter()
    for r in (finding.get('recovery', {}).get('records', []) if historical else finding['observations']):
        if not isinstance(r, dict): raise ValueError('Invalid observation')
        fields = {k:v for k,v in r.items() if k not in {'evidence_reference','record_locator'}}
        result[json.dumps(fields, sort_keys=True, ensure_ascii=True)] += 1
    return result


def compare(before_path, after_path):
    before, bref = load_report(before_path); after, aref = load_report(after_path)
    def index(report):
        result = defaultdict(list)
        for f in report['findings']:
            source = f.get('original_source_path') or f.get('evidence_relative_path') or f['source_path']
            result[(f['runner'], f['artifact_type'], source)].append(f)
        return result
    left, right = index(before), index(after); changes = []
    for key in sorted(left.keys() | right.keys()):
        a, b = left.get(key, []), right.get(key, [])
        row = {'runner':key[0], 'artifact_type':key[1], 'source_key':key[2]}
        if len(a)>1 or len(b)>1: row.update(status='ambiguous', before_matches=len(a), after_matches=len(b))
        elif not a: row.update(status='newly_observed', after_artifact_id=b[0]['id'])
        elif not b: row.update(status='not_observed_after', before_artifact_id=a[0]['id'])
        else:
            a,b=a[0],b[0];old,new=records(a),records(b)
            comparable = bool(a.get('sha256') and b.get('sha256') and a.get('hash_scope') == b.get('hash_scope'))
            def sidecars(f):
                return sorted((Path(x.get('source_path','')).name, x.get('sha256'), x.get('size_bytes')) for x in f.get('acquisition_files', []))
            old_residue,new_residue=records(a,True),records(b,True)
            same_bytes = comparable and a['sha256']==b['sha256'] and sidecars(a)==sidecars(b)
            source_status = ('unchanged' if same_bytes else 'changed') if comparable else 'indeterminate'
            def analysis_context(report,f):
                recovery=f.get('recovery',{})
                model=f.get('decoding_model',report.get('decoding_model'))
                if isinstance(model,dict):model={k:model.get(k) for k in ('sha256','metadata_prefix_sha256','tokenizer')}
                return (report.get('version'),report.get('analysis_options'),f.get('schema_adapter'),
                        recovery.get('status','not_requested'),model)
            context_same=analysis_context(before,a)==analysis_context(after,b)
            complete=all(f['status'] in {'parsed','header_only'} and f.get('recovery',{}).get('status','completed')=='completed' for f in (a,b))
            interpretation_same=old==new and old_residue==new_residue and a['status']==b['status']
            if not context_same or not complete or not comparable:
                status='indeterminate'
            elif not same_bytes:
                status='changed'
            elif not interpretation_same:
                status='analysis_changed'
            else:status='unchanged'
            row.update(source_bytes_status=source_status,
                       analysis_status='not_comparable' if not context_same or not complete else 'unchanged' if interpretation_same else 'changed',
                       analysis_context_equal=context_same,
                       interpretation_note='Record differences describe extraction results; they do not by themselves establish changed source bytes.')
            row.update(newly_observed_historical_candidates=sum((new_residue-old_residue).values()),not_observed_after_historical_candidates=sum((old_residue-new_residue).values()))
            row.update(status=status,before_artifact_id=a['id'],after_artifact_id=b['id'],before_sha256=a.get('sha256'),after_sha256=b.get('sha256'),hash_scope=b.get('hash_scope'),
                newly_observed_records=sum((new-old).values()),not_observed_after_records=sum((old-new).values()),
                before_status=a['status'],after_status=b['status'])
        changes.append(row)
    return {'comparison_schema':1, 'before':bref,'after':aref,
            'before_coverage':assess(before),'after_coverage':assess(after),
            'summary':dict(Counter(r['status'] for r in changes)), 'artifacts':changes,
            'limitations':['Missing evidence is not proof of deletion. Scope, permissions, path changes and parser versions can change results.',
                'Matching uses runner, artifact type and original path (or evidence-relative path for older reports). Renamed files are not linked automatically.',
                'Record counts compare extracted observation fields including metadata, excluding locators/references. They do not establish message edits, authorship or causation.',
                'Source-byte status is reported separately from analysis status. Options, recovery phase and decoding vocabulary can make analyses noncomparable.',
                'Hashes cover their stated scope only. SQLite sidecar hashes and extracted historical candidates are compared separately from current record counts. Reports are not authenticated evidence.'],
            'parser_versions': [before.get('version'),after.get('version')]}


def render_comparison(result):
    escape=lambda value:html.escape(str(value),quote=True)
    rows=[]
    for row in result['artifacts']:
        rows.append('<tr><td>'+escape(row['runner'])+'<br>'+escape(row['artifact_type'])+'</td><td>'+escape(row['source_key'])+'</td><td>'+escape(row['status'].replace('_',' '))+'<br><small>Source bytes: '+escape(row.get('source_bytes_status','not compared'))+'</small></td><td>'+escape(row.get('newly_observed_records','—'))+'</td><td>'+escape(row.get('not_observed_after_records','—'))+'</td></tr>')
    summary=' · '.join(escape(k.replace('_',' '))+': '+str(v) for k,v in result['summary'].items())
    details=escape(json.dumps(result,indent=2,ensure_ascii=True))
    return ('<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">'
        '<title>Case comparison</title><style>body{font:16px system-ui;background:#10191e;color:#dae5ed;max-width:1100px;margin:32px auto;padding:16px}pre,td{overflow-wrap:anywhere}pre{white-space:pre-wrap}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:12px;border-bottom:1px solid #537080;vertical-align:top}section{overflow-x:auto}summary{cursor:pointer}h2{font-size:18px}</style>'
        '<h1>Case comparison</h1><p>Not observed after does not mean deleted. Scope, permissions and parser changes can affect results.</p>'
        '<h2>'+summary+'</h2><p>Before coverage: '+escape(result['before_coverage']['status'])+' · After coverage: '+escape(result['after_coverage']['status'])+'</p>'
        '<section><table><tr><th>Artifact</th><th>Source</th><th>Result</th><th>New records</th><th>Records not observed after</th></tr>'+''.join(rows)+'</table></section>'
        '<ul>'+''.join('<li>'+escape(v)+'</li>' for v in result['limitations'])+'</ul><details><summary>Hashes, counts and full comparison details</summary><pre>'+details+'</pre></details>')
