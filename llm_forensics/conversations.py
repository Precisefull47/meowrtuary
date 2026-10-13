"""Experimental structural adapter; public exporter-informed, not version-certified."""


def parse_versioned(value):
    messages = value.get('messages') if isinstance(value, dict) else None
    if not isinstance(messages, list) or not any(isinstance(m, dict) and isinstance(m.get('versions'), list) for m in messages):
        return None
    records, issues, metadata = [], [], []
    truncated=False
    def full():return len(records)+len(issues)+len(metadata)>=10000

    def blocks(content, location, role, message_index, version_index):
        nonlocal truncated
        if not isinstance(content, list):
            issues.append({'record_locator': location, 'reason': 'expected content block array'})
            return
        for index, block in enumerate(content):
            if full():truncated=True;break
            pointer = f'{location}/{index}'
            if isinstance(block, dict) and block.get('type') == 'text' and isinstance(block.get('text'), str):
                records.append({'record_locator': pointer + '/text', 'role': role, 'text': block['text'],
                                'message_index': message_index, 'version_index': version_index,
                                'timestamp': None, 'timestamp_basis': 'not interpreted',
                                'branch_selection': 'unknown; all stored versions retained'})
                selected=messages[message_index].get('currentlySelected')
                if type(selected) is int and 0<=selected<len(messages[message_index]['versions']):
                    records[-1].update(selected_version_index=selected,is_selected_version=version_index==selected,branch_selection='stored currentlySelected index; all versions retained')
                version=messages[message_index]['versions'][version_index]
                if type(version.get('edited')) is bool: records[-1]['edited']=version['edited']
                if isinstance(version.get('senderInfo'),dict): records[-1]['sender_info']=version['senderInfo']
            else:
                issue={'record_locator': pointer, 'reason': 'unsupported content block; media content not extracted'}
                if isinstance(block,dict):
                    issue['block_type']=block.get('type') if isinstance(block.get('type'),str) else None
                    issue['stored_reference_fields']={k:v for k,v in block.items() if k in ('path','url','name','mimeType','size','fileName','filePath') and isinstance(v,(str,int,float,bool))}
                    issue['reference_meaning']='Literal stored fields only; target existence, content and schema semantics are unverified. Nothing is followed or downloaded.'
                issues.append(issue)

    for i, message in enumerate(messages):
        if full():truncated=True;break
        versions = message.get('versions') if isinstance(message, dict) else None
        if not isinstance(versions, list) or not versions:
            issues.append({'record_locator': f'/messages/{i}', 'reason': 'missing or empty versions'})
            continue
        for j, version in enumerate(versions):
            if full():truncated=True;break
            loc = f'/messages/{i}/versions/{j}'
            if not isinstance(version, dict) or version.get('role') not in ('user', 'assistant', 'system', 'tool'):
                issues.append({'record_locator': loc, 'reason': 'unsupported message role or structure'})
                continue
            role = version['role']
            present = False
            if 'content' in version:
                present = True
                blocks(version['content'], loc + '/content', role, i, j)
            if 'steps' in version:
                present = True
                steps = version['steps']
                if not isinstance(steps, list) or not steps:
                    issues.append({'record_locator': loc + '/steps', 'reason': 'missing or empty steps'})
                else:
                    for k, step in enumerate(steps):
                        if full():truncated=True;break
                        if isinstance(step,dict) and step.get('type')=='debugInfoBlock':
                            metadata.append({'record_locator':f'{loc}/steps/{k}','kind':'debug_info','value':step.get('debugInfo')})
                            continue
                        first=len(records)
                        blocks(step.get('content') if isinstance(step, dict) else None,
                               f'{loc}/steps/{k}/content', role, i, j)
                        if isinstance(step,dict) and isinstance(step.get('genInfo'),dict):
                            info=step['genInfo']
                            for record in records[first:]:
                                record['generation_info_locator']=f'{loc}/steps/{k}/genInfo'
                                record['model_name']=info.get('identifier')
                                record['model_path_identifier']=info.get('indexedModelIdentifier')
                                if isinstance(info.get('stats'),dict):record['generation_statistics']=info['stats']
            if not present:
                issues.append({'record_locator': loc, 'reason': 'no recognized content container'})
    if truncated:issues.append({'record_locator':'/messages','reason':'Record limit reached: first 10000 records/metadata/issues retained'})
    chat_metadata={k:value[k] for k in ('name','createdAt','userLastMessagedAt','assistantLastMessagedAt') if k in value}
    if chat_metadata:metadata.append({'record_locator':'/','kind':'conversation_metadata','raw_fields':chat_metadata,'limitations':'Conversation-level values; not individual-message timestamps.'})
    return {'validation':'Versioned text-block schema observed on LM Studio 0.4.25 build 1, macOS; other versions not certified.','conversation_metadata':metadata,'observations': records, 'unparsed_records': issues, 'schema_adapter': 'lmstudio-versioned-blocks-experimental',
            'status': 'partial' if issues and records else ('unsupported_schema' if not records else 'parsed')}
