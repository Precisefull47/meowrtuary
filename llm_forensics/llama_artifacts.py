"""Bounded structural inspection of observed llama.cpp logs and v10 sessions."""
import re
import struct

LOG_SIGNATURE = re.compile(rb'^\d+\.\d+\.\d+\.\d+ [IWE] llama_completion: llama backend init\r?$', re.M)


def inspect_llama(data):
    if data.startswith(b'nsgg'):
        if len(data)<12:
            return {'artifact_type':'llama_session','status':'invalid_header','observations':[]}
        version,count=struct.unpack_from('<II',data,4)
        header={'record_locator':'bytes 0–11','session_version':version,'declared_token_count':count}
        if version!=10:
            return {'artifact_type':'llama_session','status':'unsupported_version','observations':[header]}
        end=12+4*count
        if count>1_000_000 or end>=len(data):
            return {'artifact_type':'llama_session','status':'invalid_structure','observations':[header]}
        tokens=list(struct.unpack_from(f'<{count}i',data,12))
        if any(t<0 for t in tokens):
            return {'artifact_type':'llama_session','status':'invalid_structure','observations':[header]}
        return {'artifact_type':'llama_session','status':'partial','observations':[
            {**header,'record_locator':f'bytes 0–{end-1}','token_ids':tokens,'token_byte_offset':12,
             'unparsed_state_bytes':len(data)-end,'timestamp':None,'timestamp_basis':'not stored in parsed header'}],
            'limitations':['Token IDs require the matching vocabulary to interpret. This parser does not decode text or validate the remaining model state.',
                            'No roles, model identity, wall-clock timestamps or deletion times are inferred. Signature alone is not proof of execution.']}
    if not LOG_SIGNATURE.search(data[:16384]):return None
    try:text=data.decode('utf-8')
    except UnicodeError:return {'artifact_type':'llama_log','status':'parse_error','observations':[]}
    records=[];offset=0;truncated=False
    for number,line in enumerate(text.splitlines(keepends=True),1):
        if len(records)>=10000:truncated=True;break
        raw=line.encode('utf-8')
        if line.strip():records.append({'record_locator':f'line {number}, byte offset {offset}','byte_offset':offset,
            'text':line.rstrip('\r\n'),'timestamp':None,'timestamp_basis':'log clock not interpreted as wall time',
            'content_class':'raw log text; prompt and response boundaries not inferred'})
        offset+=len(raw)
    return {'artifact_type':'llama_log','status':'partial' if truncated else 'parsed','observations':records,
        'limitations':(['Record limit reached: first 10000 nonempty lines only.'] if truncated else [])+['Observed llama-completion log signature only; other builds/logging settings may differ.',
                        'Raw lines can interleave prompts, generated text and diagnostics. Roles and wall-clock times are not inferred.']}
