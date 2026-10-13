"""Evidence chronology with explicit time semantics and unplaced records."""
import csv
from datetime import datetime, timedelta, timezone
import json

LIMITATIONS = [
    'Stored times are not independently verified; source clocks may be wrong.',
    'File modification times may reflect copying or acquisition, not model use.',
    'Historical residue may be superseded or deleted; its message time is not a deletion time.',
    'Records without an explicit timezone remain undated; no timezone is guessed.',
    'Similar records are retained separately. Ordering does not prove causation or authorship.',
]


def normalize(value):
    if not isinstance(value,str):return None
    try:
        parsed=datetime.fromisoformat(value.replace('Z','+00:00'))
        if parsed.tzinfo is None or parsed.utcoffset() is None:return None
        return parsed.astimezone(timezone.utc).isoformat(timespec='microseconds')
    except (ValueError,OverflowError):return None


def epoch_ms(value):
    if type(value) is not int:return None
    try:return (datetime(1970,1,1,tzinfo=timezone.utc)+timedelta(milliseconds=value)).isoformat(timespec='microseconds')
    except (OverflowError,ValueError):return None


def build_timeline(report):
    events=[];undated=[]
    def add(finding,kind,locator,raw,normalized,basis,record=None,context=None):
        record=record or {}
        event={'event_id':f'event-{len(events)+len(undated)+1}','event_kind':kind,
            'timestamp_utc':normalized,'timestamp_raw':raw,'timestamp_basis':basis,
            'artifact_id':finding['id'],'runner':finding['runner'],'artifact_type':finding['artifact_type'],
            'source_path':finding['source_path'],'original_source_path':finding.get('original_source_path'),'source_sha256':finding.get('sha256'),
            'hash_scope':finding.get('hash_scope'),'source_status':finding['status'],
            'source_changed_during_read':finding.get('source_changed_during_read',False),
            'record_locator':locator,'record_context':context,
            'text':record.get('text'),'role':record.get('role'),'chat_id':record.get('chat_id'),
            'model_name':record.get('model_name'),'is_selected_version':record.get('is_selected_version'),
            'current_record_comparison':record.get('current_record_comparison'),
            'decoding_status':record.get('decoding_status'),'artifact_context':finding.get('artifact_context'),
            'acquisition_files':finding.get('acquisition_files',[])}
        (events if normalized else undated).append(event)
    for f in report['findings']:
        raw=f.get('filesystem_mtime_utc')
        if raw is not None:
            add(f,'file_modified','filesystem metadata',raw,normalize(raw),'filesystem mtime; not an interaction or deletion time')
        for group,records in [('observations',f.get('observations',[])),('historical_residue',f.get('recovery',{}).get('records',[]))]:
            for index,record in enumerate(records):
                raw=record.get('timestamp_raw',record.get('timestamp'))
                time=normalize(record.get('timestamp'))
                # Preserve explicit raw offsets even if an adapter has not normalized them.
                if time is None:time=normalize(raw)
                kind='historical_residue' if group=='historical_residue' else ('message_record' if record.get('role') else 'artifact_record')
                add(f,kind,record.get('record_locator'),raw,time,record.get('timestamp_basis','not stored or not interpreted'),record,{'group':group,'index':index})
        for index,metadata in enumerate(f.get('conversation_metadata',[])):
            if metadata.get('kind')!='conversation_metadata':continue
            for key in ('createdAt','userLastMessagedAt','assistantLastMessagedAt'):
                if key not in metadata.get('raw_fields',{}):continue
                raw=metadata['raw_fields'][key]
                add(f,'conversation_metadata','/'+key,raw,epoch_ms(raw),
                    'LM Studio stored conversation-level Unix milliseconds; not an individual-message timestamp',
                    context={'group':'conversation_metadata','index':index,'field':key})
    events.sort(key=lambda e:(e['timestamp_utc'],e['source_path'],str(e['record_locator']),e['event_kind'],e['event_id']))
    return {'events':events,'undated_records':undated,'summary':{'dated_events':len(events),'undated_records':len(undated),
        'file_time_events':sum(e['event_kind']=='file_modified' for e in events)},'limitations':LIMITATIONS,
        'decoding_model':report.get('decoding_model')}


CSV_FIELDS=('event_id','timestamp_utc','timestamp_raw','timestamp_basis','event_kind','runner','artifact_type','artifact_id','source_path','original_source_path','source_sha256','hash_scope','source_status','record_locator','role','chat_id','model_name','text','current_record_comparison','decoding_status','csv_escaped_fields')


def write_timeline(timeline,output):
    (output/'timeline.json').write_text(json.dumps(timeline,indent=2,ensure_ascii=True),encoding='utf-8')
    with (output/'timeline.csv').open('w',encoding='utf-8',errors='backslashreplace',newline='') as handle:
        writer=csv.DictWriter(handle,fieldnames=CSV_FIELDS);writer.writeheader()
        for event in timeline['events']+timeline['undated_records']:
            row={};escaped=[]
            for key in CSV_FIELDS[:-1]:
                value=event.get(key);value='' if value is None else str(value)
                # Spreadsheet programs can evaluate evidence strings as formulas.
                if value and (value[0] in '\t\r\n' or value.lstrip().startswith(('=','+','-','@'))):
                    value="'"+value;escaped.append(key)
                row[key]=value
            row['csv_escaped_fields']=','.join(escaped);writer.writerow(row)
