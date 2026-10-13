"""Self-contained reports; all evidence content is escaped and rendered as text."""
import html
import json


def compact(value):
    """Presentation-only pruning. Preserve false, zero and nonempty evidence text."""
    if isinstance(value, dict):
        return {k: cleaned for k, v in value.items() if (cleaned := compact(v)) not in (None, "", [], {})}
    if isinstance(value, list):
        return [cleaned for v in value if (cleaned := compact(v)) not in (None, "", [], {})]
    return value



def render_timeline(timeline):
    if not timeline:return ""
    escape=lambda value:html.escape(str(value).encode('utf-8',errors='backslashreplace').decode('utf-8'),quote=True)
    labels={'file_modified':'File modified','message_record':'Message record','historical_residue':'Historical residue','artifact_record':'Artifact record','conversation_metadata':'Chat metadata'}
    def table(events):
        rows=[]
        for event in events[:500]:
            kind=event['event_kind'];when=event['timestamp_utc'] or 'Unknown time'
            snippet=event.get('text') or event.get('record_locator') or ''
            if len(snippet)>240:snippet=snippet[:240]+'…'
            rows.append(f'<tr data-timeline-row data-kind="{escape(kind)}"><td>{escape(when)}</td><td>{escape(labels[kind])}<br><small>{escape(event["timestamp_basis"])}</small></td><td>{escape(event["runner"])}</td><td>{escape(snippet)}<br><small>{escape(event["artifact_id"])} · {escape(event["record_locator"])}</small></td></tr>')
        return '<div class="timeline-scroll"><table><thead><tr><th>Time (UTC)</th><th>Evidence type</th><th>Runner</th><th>Record</th></tr></thead><tbody>'+''.join(rows)+'</tbody></table></div>'
    dated=timeline['events'];unknown=timeline['undated_records'];summary=timeline['summary']
    result=f'<section id="timeline"><h2>Evidence timeline</h2><p>{len(dated)} dated events · {len(unknown)} undated records · {summary["file_time_events"]} file-time events</p><p>File times may reflect acquisition. Historical message times do not establish when deletion occurred. Full provenance and unabridged text are in timeline.json; spreadsheet-safe values are in timeline.csv.</p><label for="timeline-kind">Evidence type </label><select id="timeline-kind"><option value="all">All evidence</option>'+''.join(f'<option value="{key}">{value}</option>' for key,value in labels.items())+'</select>'
    if dated:result+=table(dated)
    if unknown:result+='<details><summary>Records with unknown time ('+str(len(unknown))+')</summary>'+table(unknown)+'</details>'
    if len(dated)>500 or len(unknown)>500:result+='<p>HTML shows the first 500 records in each group; JSON and CSV include every timeline record.</p>'
    return result+'</section>'


def render_html(report):
    escape = lambda x: html.escape(str(x).encode('utf-8',errors='backslashreplace').decode('utf-8'), quote=True)
    def section(title, value, explanation=""):
        cleaned = compact(value)
        if not cleaned:
            return ""
        return f'<section><h2>{escape(title)}</h2>{explanation}<details><summary>Show details</summary><pre>{escape(json.dumps(cleaned, ensure_ascii=True, indent=2))}</pre></details></section>'

    coverage = report.get('coverage_summary', {})
    coverage_html = ''
    if coverage:
        gap_rows = ''.join('<tr><td>'+escape(g.get('path',g.get('source_path','Scope')) or 'Scope')+'</td><td>'+escape(g.get('status','unknown'))+'</td><td>'+escape(g.get('detail','Review artifact limitations'))+'</td></tr>' for g in coverage['gaps'])
        coverage_html = '<section class="notice"><h2>Scan coverage: '+escape(coverage['status'].replace('_',' '))+'</h2><p>'+escape(coverage['meaning'])+'</p><p>'+escape(coverage['scope_limit'])+'</p>'
        if gap_rows: coverage_html += '<div class="timeline-scroll"><table><tr><th>Location</th><th>Gap</th><th>Details</th></tr>'+gap_rows+'</table></div>'
        coverage_html += section('Locations checked', coverage['locations'])+'</section>'
    cards = []
    for f in report["findings"]:
        observations = []
        for record in f["observations"]:
            observations.append("<details><summary>" + escape(record["record_locator"]) +
                                "</summary><pre>" + escape(json.dumps(compact(record), ensure_ascii=True, indent=2)) + "</pre></details>")
        metadata = []
        if f.get('original_source_path'):
            metadata.append(f"<p class='path'>Original source: {escape(f['original_source_path'])}</p>")
        if f.get('filesystem_mtime_utc'):
            metadata.append(f"<p>File modified: {escape(f['filesystem_mtime_utc'])}<br><small>Filesystem time only; not an interaction timestamp.</small></p>")
        if f.get('sha256'):
            scope = f"<br>Scope: {escape(f['hash_scope'])}" if f.get('hash_scope') else ""
            metadata.append(f"<p class='path'>SHA-256: {escape(f['sha256'])}{scope}</p>")
        if f.get('validation'):
            metadata.append(f"<p>{escape(f['validation'])}</p>")
        if f.get('limitations'):
            metadata.append('<ul>' + ''.join('<li>'+escape(x)+'</li>' for x in f['limitations']) + '</ul>')
        conversation_meta = section('Conversation metadata', f.get('conversation_metadata'))
        recovery = section('Historical message residue · experimental', f.get('recovery'), '<p>These candidates may be deleted or superseded records. They are separate from current messages.</p>')
        unsupported = section('Unsupported records', f.get('unparsed_records'))
        cards.append(f"""<article data-runner="{escape(f['runner'])}" data-status="{escape(f['status'])}"><div class="tags">{escape(f['runner'])} · {escape(f['artifact_type'])} · {escape(f['status'])}</div>
<h2>{escape(f['id'])}</h2><p class="path">{escape(f['source_path'])}</p>
{''.join(metadata)}{unsupported}{conversation_meta}{recovery}{''.join(observations)}</article>""")
    return """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Local LLM Forensics · Evidence report</title><style>
:root{font-family:system-ui,sans-serif;color:#dae5ed;background:#10191e}body{max-width:1050px;margin:28px auto;padding:0 20px}
h1{font-size:36px;margin-bottom:12px}h2{font-size:19px}.eyebrow,.tags{color:#7dd8c4}p,li{line-height:1.45}p{margin:8px 0}ul{margin:8px 0;padding-left:20px}section{margin:16px 0}small{color:#aebcc6}
article,.notice{background:#19262e;border:1px solid #334650;border-radius:12px;padding:16px;margin:12px 0}
.path,pre{overflow-wrap:anywhere;white-space:pre-wrap;font-size:13px}pre{background:#10191e;padding:10px;border-radius:6px;margin:6px 0}
.timeline-scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;vertical-align:top;border-bottom:1px solid #334650;padding:10px;overflow-wrap:anywhere}select{padding:8px;margin:8px;background:#19262e;color:#fff}td:first-child{min-width:150px}
summary{cursor:pointer;padding:5px 0}input{box-sizing:border-box;width:100%;padding:15px;background:#19262e;color:#fff;border:1px solid #537080;border-radius:8px}
[hidden]{display:none}a{color:#7dd8c4}@media print{body{background:white;color:black}article,.notice,pre{background:white;color:black}input{display:none}}
</style><p class="eyebrow">LOCAL LLM FORENSICS / EXPERIMENTAL PROTOTYPE</p><h1>Evidence, with its source.</h1>
<p><small>Empty fields are hidden in this view; structured exports retain the original values.</small></p><p>Existing-file triage. Findings indicate artifacts; they do not establish a person's intent or authorship.</p>
""" + f"""<div class="notice"><strong>{len(report['findings'])} candidate artifacts · {len(report['issues'])} scan issues</strong>
<p class="path">Evidence folder: {escape(report['evidence_root'])}</p>
<p>Evidence OS: {escape(report.get('source_os', 'unknown'))} · Analysis host: {escape(report.get('analysis_host_os', 'unknown'))}</p>
<ul>{''.join('<li>'+escape(x)+'</li>' for x in report['limitations'])}</ul></div>
<label for="runner-filter">Runner </label><select id="runner-filter"><option value="all">All runners</option>{''.join('<option value="'+escape(v)+'">'+escape(v)+'</option>' for v in sorted(set(f['runner'] for f in report['findings'])))}</select>
<label for="status-filter">Status </label><select id="status-filter"><option value="all">All statuses</option>{''.join('<option value="'+escape(v)+'">'+escape(v)+'</option>' for v in sorted(set(f['status'] for f in report['findings'])))}</select>
<label for="filter">Filter artifacts by runner, source path, or extracted text</label><input id="filter" type="search" placeholder="Search this report…">
{coverage_html}
{render_timeline(report.get('timeline'))}
{''.join(cards) or '<p>No supported candidate artifacts found within the selected scope.</p>'}
{section('Supplied decoding model', report.get('decoding_model'), '<p>Decoded session text is conditional on this vocabulary. The cache does not authenticate the model association.</p>')}
{section('Evidence acquisition', report.get('acquisition'), '<p>Raw captures and hashes are preserved in acquisition-manifest.json. Quarantined files are not parsed. Matching reads do not establish an atomic live snapshot.</p>')}
{section('Discovery locations', report.get('locations'))}
{section('Discovery coverage', report.get('discovery_coverage'), '<p>Counts refer to matching files, not successful extraction. Zero matches apply only to the readable selected scope.</p>')}
{section('Scan issues', report.get('issues'))}
<p>Parser {escape(report['version'])} · Completed {escape(report['scan_finished_utc'])}</p>
""" + """<script>function filterEvidence(){const q=document.getElementById('filter').value.toLowerCase();const runner=document.getElementById('runner-filter').value;const status=document.getElementById('status-filter').value;document.querySelectorAll('article').forEach(a=>a.hidden=!a.textContent.toLowerCase().includes(q)||(runner!=='all'&&a.dataset.runner!==runner)||(status!=='all'&&a.dataset.status!==status));const picker=document.getElementById('timeline-kind');const kind=picker?picker.value:'all';document.querySelectorAll('[data-timeline-row]').forEach(r=>r.hidden=!r.textContent.toLowerCase().includes(q)||(kind!=='all'&&r.dataset.kind!==kind));}document.getElementById('filter').addEventListener('input',filterEvidence);document.getElementById('runner-filter').addEventListener('change',filterEvidence);document.getElementById('status-filter').addEventListener('change',filterEvidence);const picker=document.getElementById('timeline-kind');if(picker)picker.addEventListener('change',filterEvidence);</script></html>"""
