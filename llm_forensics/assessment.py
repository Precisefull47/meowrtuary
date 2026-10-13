"""Explain bounded scan completeness and attach per-record evidence references."""
from collections import Counter

GOOD = {'parsed', 'header_only'}


def assess(report):
    findings = report.get('findings', [])
    acquisition = report.get('acquisition', {})
    locations = report.get('locations') or acquisition.get('scopes') or [
        {'path': report.get('evidence_root'), 'status': 'scanned'}]
    gaps = [dict(i) for i in report.get('issues', [])]
    for location in locations:
        if location.get('status') not in {'scanned', 'enumerated', 'not_found'}:
            gaps.append({'path': location.get('path', location.get('source_path')),
                         'status': location.get('status'), 'detail': location.get('detail', 'Scope was not fully checked')})
    for finding in findings:
        if finding['status'] not in GOOD or finding.get('source_changed_during_read'):
            gaps.append({'path': finding.get('original_source_path', finding['source_path']),
                         'status': 'source_changed' if finding.get('source_changed_during_read') else finding['status'], 'artifact_id': finding['id']})
        recovery=finding.get('recovery')
        if recovery is not None and recovery.get('status')!='completed':
            gaps.append({'path':finding.get('original_source_path',finding['source_path']),
                         'status':'recovery_'+str(recovery.get('status','unknown')),
                         'artifact_id':finding['id'],'detail':recovery.get('reason') or 'Requested historical recovery did not complete'})
    if acquisition.get('status') not in (None, 'complete'):
        gaps.append({'status': 'acquisition_' + str(acquisition['status']), 'detail': 'Capture did not complete without gaps'})
    seen = set(); unique = []
    for gap in gaps:
        key = (gap.get('path', gap.get('source_path')), gap.get('status'), gap.get('detail'))
        if key not in seen: unique.append(gap); seen.add(key)
    usable = any(f['status'] in GOOD or f.get('observations') for f in findings)
    status = ('partial' if usable else 'blocked') if unique else 'complete_within_scope'
    return {'status': status, 'meaning': {
        'partial': 'Some evidence was examined, but capture or extraction has gaps.',
        'blocked': 'No usable extraction was obtained and one or more checks failed.',
        'complete_within_scope': 'Selected supported checks finished without reported gaps; this is not a whole-system coverage claim.'}[status],
        'candidate_artifacts': len(findings), 'files_considered': report.get('files_considered', 0),
        'artifact_status_counts': dict(Counter(f['status'] for f in findings)),
        'locations': locations, 'gaps': unique,
        'negative_result': 'No findings does not prove absence of local LLM use.',
        'scope_limit': 'Known paths and supported formats only. Unrecognized files, unselected users/volumes and unavailable deleted data may be missed.'}


def enrich(report):
    report['coverage_summary'] = assess(report)
    for finding in report['findings']:
        groups = [('current', finding.get('observations', [])),
                  ('historical_candidate', finding.get('recovery', {}).get('records', []))]
        for kind, records in groups:
            for index, record in enumerate(records, 1):
                record['evidence_reference'] = {
                    'reference_id': f"{finding['id']}:{kind}:{index}",
                    'artifact_id': finding['id'], 'record_kind': kind,
                    'original_source_path': finding.get('original_source_path', finding['source_path']),
                    'analyzed_path': finding['source_path'], 'source_sha256': finding.get('sha256'),
                    'hash_scope': finding.get('hash_scope'),
                    'record_locator': record.get('record_locator'),
                    'byte_offset': record.get('byte_offset'), 'byte_length': record.get('byte_length'),
                    'page_number': record.get('page_number'),
                    'extraction_method': ('sqlite_intact_freelist' if kind == 'historical_candidate' else finding.get('schema_adapter', finding['artifact_type'])),
                    'parser_version': report['version'],
                    'sidecars': finding.get('acquisition_files', []),
                    'interpretation': 'A reference identifies extracted evidence, not its author or authenticity.'}
    return report
