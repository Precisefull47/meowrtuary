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
    conversations = []
    for f in report["findings"]:
        observations = []
        for record in f["observations"]:
            if record.get('text') is not None:
                observations.append('<div class="message"><strong>'+escape(record.get('role','Record'))+'</strong><pre>'+escape(record['text'])+'</pre></div>')
            observations.append("<details><summary>" + escape(record["record_locator"]) +
                                "</summary><pre>" + escape(json.dumps(compact(record), ensure_ascii=True, indent=2)) + "</pre></details>")
        messages = [r for r in f['observations'] if r.get('role') and isinstance(r.get('text'), str)]
        if messages:
            message_html = ''.join('<div class="message"><strong>'+escape(r['role'])+'</strong><pre>'+escape(r['text'])+'</pre><details><summary>Source reference · '+escape(r['record_locator'])+'</summary><pre>'+escape(json.dumps(compact(r), ensure_ascii=True, indent=2))+'</pre></details></div>' for r in messages)
            conversations.append('<article><div class="tags">'+escape(f['runner'])+' · '+escape(f['status'])+'</div><h2>'+escape(f['id'])+'</h2><p class="path">'+escape(f.get('original_source_path') or f['source_path'])+'</p><p><small>Grouped by source artifact; stored record order is not necessarily chronological. Review source references for message versions and timestamps.</small></p>'+message_html+'</article>')
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
<details class="provenance"><summary>Source details, hashes and limitations</summary>{''.join(metadata)}</details>{unsupported}{conversation_meta}{recovery}{''.join(observations)}</article>""")
    from .report_workspace import STYLE, SCRIPT
    findings = report['findings']
    runner_rows = ''.join('<div class="runner-row"><span>'+escape(runner)+'</span><strong>'+str(sum(f['runner']==runner for f in findings))+' artifacts</strong></div>' for runner in sorted({f['runner'] for f in findings}))
    return """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>meowrtuary · Evidence dashboard</title><style>""" + STYLE + """</style></head><body>
<header><pre aria-hidden="true"> /\\_/\\
( o.o )</pre><div><h1>meowrtuary</h1><small>Evidence workspace</small></div></header>
<div class="workspace"><nav aria-label="Report sections"><a href="#overview">Overview</a><a href="#conversations">Conversations</a><a href="#evidence">Evidence</a><a href="#timeline">Timeline</a></nav><main>
""" + f"""<section id="overview" data-panel><div class="eyebrow">CASE OVERVIEW</div><h2 tabindex="-1">Evidence dashboard</h2>
<p class="path">Evidence folder: {escape(report['evidence_root'])}</p><p><small>Analysis completed {escape(report['scan_finished_utc'])}</small></p>
<div class="metrics"><div class="notice"><strong>{len(findings)}</strong><span>Candidate artifacts</span></div><div class="notice"><strong>{sum(len(f['observations']) for f in findings)}</strong><span>Extracted records</span></div><div class="notice"><strong>{len(coverage.get('gaps', []))}</strong><span>Coverage gaps</span></div></div>
{coverage_html}<div class="notice"><h2>Evidence by runner</h2>{runner_rows or '<p>No supported artifacts found.</p>'}</div>
<div class="notice"><h2>Scope and interpretation</h2><p>Evidence OS: {escape(report.get('source_os','unknown'))} · Analysis host: {escape(report.get('analysis_host_os','unknown'))}</p><p>Existing-file triage. Findings indicate artifacts; they do not establish a person's intent or authorship.</p><ul>{''.join('<li>'+escape(x)+'</li>' for x in report['limitations'])}</ul></div>
{section('Evidence acquisition', report.get('acquisition'), '<p>Raw captures and hashes are preserved in acquisition-manifest.json. Quarantined files are not parsed. Matching reads do not establish an atomic live snapshot. Hashes displayed here are recorded values, not a fresh integrity verification.</p>')}
{section('Discovery locations', report.get('locations'))}
{section('Discovery coverage', report.get('discovery_coverage'), '<p>Counts refer to matching files, not successful extraction. Zero matches apply only to the readable selected scope.</p>')}
{section('Scan issues', report.get('issues'))}</section>
<section id="conversations" data-panel><div class="eyebrow">EXTRACTED MESSAGES</div><h2 tabindex="-1">Conversations</h2><p>Role-labelled text from parsed observations. Historical residue and unsupported records remain in Evidence, separate from these messages.</p>{''.join(conversations) or '<p>No role-labelled messages were extracted within the selected scope.</p>'}</section>
<section id="evidence" data-panel><div class="eyebrow">ARTIFACT CATALOGUE</div><h2 tabindex="-1">Evidence</h2>
<div class="filters"><label>Runner <select id="runner-filter"><option value="all">All runners</option>{''.join('<option value="'+escape(v)+'">'+escape(v)+'</option>' for v in sorted({f['runner'] for f in findings}))}</select></label>
<label>Status <select id="status-filter"><option value="all">All statuses</option>{''.join('<option value="'+escape(v)+'">'+escape(v)+'</option>' for v in sorted({f['status'] for f in findings}))}</select></label></div>
<label for="filter">Search source paths, extracted text and metadata</label><input id="filter" type="search" placeholder="Search evidence…"><p id="result-count" role="status" aria-live="polite"></p><p id="no-matches" hidden>No artifacts match these filters.</p>
{''.join(cards) or '<p>No supported candidate artifacts found within the selected scope.</p>'}
{section('Supplied decoding model', report.get('decoding_model'), '<p>Decoded session text is conditional on this vocabulary. The cache does not authenticate the model association.</p>')}</section>
<section id="timeline" data-panel><div class="eyebrow">CHRONOLOGY</div><h2 tabindex="-1">Timeline</h2><label for="timeline-search">Search timeline</label><input id="timeline-search" type="search" placeholder="Search events…">
{render_timeline(report.get('timeline')).replace('id="timeline"', 'class="timeline-content"') or '<p>No timeline data was generated for this report.</p>'}<p id="timeline-count" role="status" aria-live="polite"></p></section>
<footer><button id="print-section" type="button">Print this section</button><p id="print-scope">Print the selected section with current filters and expanded details. Structured exports contain the full records.</p>Parser {escape(report['version'])} · Empty fields are hidden; structured exports retain original values.</footer></main></div>
""" + '<script>'+SCRIPT+'</script></body></html>'
