"""Experimental intact-record carving for one observed Ollama message schema.

No prior conversation text is used. Only complete records on freelist pages are
accepted; fragmented/overflow records and overwritten headers are not repaired.
"""
import re,struct
from datetime import datetime,timezone

FIELDS=('id','chat_id','role','content','thinking','stream','model_name','model_cloud','model_ollama_host','created_at','updated_at','thinking_time_start','thinking_time_end','tool_result')
UUID=re.compile(rb'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')


def varint(data,offset,end):
    value=0
    for i in range(9):
        if offset>=end:raise ValueError('truncated varint')
        byte=data[offset];offset+=1
        if i==8:return (value<<8)|byte,offset
        value=(value<<7)|(byte&127)
        if byte<128:return value,offset
    raise ValueError('invalid varint')


def length(serial):
    if serial==0 or serial in (8,9):return 0
    if 1<=serial<=6:return (1,2,3,4,6,8)[serial-1]
    if serial==7:return 8
    if serial>=12:return (serial-12)//2
    raise ValueError('reserved serial type')


def decode(data,start,anchor,end):
    header,pos=varint(data,start,end)
    if start+header!=anchor:raise ValueError('header/body boundary mismatch')
    types=[]
    while pos<anchor:
        serial,pos=varint(data,pos,anchor);types.append(serial)
    if len(types)!=len(FIELDS) or types[0]!=0 or types[1]!=85:raise ValueError('schema mismatch')
    values=[];pos=anchor
    for serial in types:
        size=length(serial)
        if pos+size>end:raise ValueError('overflow or truncated record')
        raw=data[pos:pos+size];pos+=size
        if serial==0:value=None
        elif serial==8:value=0
        elif serial==9:value=1
        elif 1<=serial<=6:value=int.from_bytes(raw,'big',signed=True)
        elif serial==7:value=struct.unpack('>d',raw)[0]
        elif serial%2:value=raw.decode('utf-8')
        else:value=raw
        values.append(value)
    row=dict(zip(FIELDS,values))
    if row['role'] not in ('user','assistant','system','tool'):raise ValueError('invalid role')
    if not isinstance(row['content'],str) or not isinstance(row['thinking'],str):raise ValueError('invalid content')
    for field in ('created_at','updated_at'):
        if not isinstance(row[field],str):raise ValueError('invalid time')
        dt=datetime.fromisoformat(row[field].replace('Z','+00:00'))
        if not 2000<=dt.year<=2100:raise ValueError('implausible time')
    for field in ('stream','model_cloud','model_ollama_host'):
        if row[field] not in (None,0,1):raise ValueError('invalid flag')
    for field in ('model_name','thinking_time_start','thinking_time_end','tool_result'):
        if row[field] is not None and not isinstance(row[field],str):raise ValueError('invalid optional field')
    return row,pos


def carve_freelist(data):
    if len(data)<100 or data[:16]!=b'SQLite format 3\0':raise ValueError('not SQLite')
    size=int.from_bytes(data[16:18],'big');size=65536 if size==1 else size
    if size<512 or size>65536 or size&(size-1) or len(data)%size:raise ValueError('invalid page geometry')
    if int.from_bytes(data[56:60],'big')!=1:raise ValueError('only UTF-8 supported')
    reserved=data[20];end_page=size-reserved
    if end_page<480:raise ValueError('invalid reserved region')
    trunk=int.from_bytes(data[32:36],'big');pages={};visited=set()
    while trunk:
        if trunk in visited or trunk in pages or not 1<trunk<=len(data)//size:raise ValueError('invalid freelist chain')
        visited.add(trunk);base=(trunk-1)*size
        next_trunk=int.from_bytes(data[base:base+4],'big');count=int.from_bytes(data[base+4:base+8],'big')
        if count>(end_page-8)//4:raise ValueError('invalid freelist count')
        pages[trunk]=8+4*count
        for i in range(count):
            page=int.from_bytes(data[base+8+4*i:base+12+4*i],'big')
            if not 1<page<=len(data)//size or page in pages:raise ValueError('invalid freelist leaf')
            pages[page]=0
        trunk=next_trunk
    if len(pages)!=int.from_bytes(data[36:40],'big'):raise ValueError('freelist page count mismatch')
    records=[];seen=set()
    for page,skip in sorted(pages.items()):
        base=(page-1)*size;end=base+end_page
        for match in UUID.finditer(data,base+skip,end):
            for start in range(max(base+skip,match.start()-128),match.start()):
                try:row,finish=decode(data,start,match.start(),end)
                except (ValueError,UnicodeError,OverflowError):continue
                if start in seen:continue
                seen.add(start)
                dt=datetime.fromisoformat(row['created_at'].replace('Z','+00:00'))
                records.append({'record_locator':f'freelist page {page}, record byte offset {start}',
                    'byte_offset':start,'byte_length':finish-start,'page_number':page,'role':row['role'],'text':row['content'],
                    'chat_id':row['chat_id'],'model_name':row['model_name'],'timestamp_raw':row['created_at'],
                    'timestamp':dt.astimezone(timezone.utc).isoformat() if dt.tzinfo else None,
                    'timestamp_basis':'carved stored created_at; offset required for normalization',
                    'updated_at':row['updated_at'],'thinking':row['thinking'],
                    'recovery_class':'intact record candidate on freelist page',
                    'limitations':'Row ID not recovered. Historical residue may be a superseded or deleted record; deletion time unknown.'})
    return records


def main():
    """Opt-in analysis of an acquired, checkpointed database; never opens SQLite."""
    import argparse
    import hashlib
    import json
    from pathlib import Path
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('database', type=Path, help='Acquired Ollama database copy (UTF-8, observed 14-column schema)')
    parser.add_argument('--output', type=Path, required=True, help='New JSON file outside the evidence directory')
    args = parser.parse_args()
    source = args.database.resolve()
    output = args.output.resolve()
    try:
        if source.parent == output.parent or source.parent in output.parents:
            raise ValueError('Output must be outside the evidence directory')
        wal = Path(str(source) + '-wal')
        if wal.exists() and wal.stat().st_size:
            raise ValueError('Nonempty WAL: this experimental carver requires a checkpointed evidence copy')
        with source.open('rb') as handle:
            data = handle.read(128 * 1024 * 1024 + 1)
        if len(data) > 128 * 1024 * 1024:
            raise ValueError('Database exceeds 128 MiB limit')
        records = carve_freelist(data)
        result = {'source_path': str(source), 'source_sha256': hashlib.sha256(data).hexdigest(),
                  'records': records, 'limitations': 'Experimental schema-specific candidates, including duplicate and superseded versions. No prior text used. Only complete contiguous freelist records; no overflow recovery. Does not establish deletion or deletion time. Analyze an acquired static copy.'}
        with output.open('x', encoding='utf-8') as handle:
            json.dump(result, handle, indent=2, ensure_ascii=False)
    except (ValueError, OSError) as exc:
        parser.exit(1, f'Carving failed: {exc}\n')
    print(f'{len(records)} intact record candidates; exported to {ascii(str(output))}')


if __name__ == '__main__':
    main()
