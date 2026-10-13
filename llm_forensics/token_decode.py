"""Offline, bounded GPT-2 byte-vocabulary decoding from an operator-supplied GGUF.

No model execution. The session header does not authenticate the supplied model.
"""
from .acquisition import unlinked
import hashlib
import os
from pathlib import Path
import re
import stat
import struct

MAX_METADATA=64*1024*1024
MAX_ITEMS=1_000_000
FORMATS={0:'B',1:'b',2:'H',3:'h',4:'I',5:'i',6:'f',7:'?',10:'Q',11:'q',12:'d'}
WANTED={'tokenizer.ggml.model','tokenizer.ggml.tokens','tokenizer.ggml.token_type','general.name'}


class Reader:
    def __init__(self,stream):
        self.stream=stream;self.offset=0;self.digest=hashlib.sha256()
    def read(self,n):
        if n<0 or self.offset+n>MAX_METADATA:raise ValueError('GGUF metadata exceeds 64 MiB limit')
        value=self.stream.read(n)
        if len(value)!=n:raise ValueError('Truncated GGUF metadata')
        self.offset+=n;self.digest.update(value)
        return value
    def number(self,fmt):return struct.unpack('<'+fmt,self.read(struct.calcsize(fmt)))[0]
    def string(self):
        size=self.number('Q')
        if size>16*1024*1024:raise ValueError('GGUF string exceeds limit')
        return self.read(size).decode('utf-8')
    def value(self,kind,keep):
        if kind in FORMATS:
            result=self.number(FORMATS[kind]);return result if keep else None
        if kind==8:
            result=self.string();return result if keep else None
        if kind==9:
            element=self.number('I');count=self.number('Q')
            if count>MAX_ITEMS:raise ValueError('GGUF array exceeds item limit')
            if element not in FORMATS and element!=8:raise ValueError('Unsupported GGUF array element type')
            if not keep and element in FORMATS:
                self.read(count*struct.calcsize(FORMATS[element]));return None
            values=[]
            for _ in range(count):
                value=self.value(element,keep)
                if keep:values.append(value)
            return values if keep else None
        raise ValueError('Unknown GGUF metadata type')


def load_vocabulary(path):
    path=unlinked(Path(path))
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:
        raise ValueError('Decode model must be a regular unlinked file')
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):raise ValueError('Decode model is not a regular file')
        reader=Reader(stream)
        if reader.read(4)!=b'GGUF' or reader.number('I') not in (2,3):
            raise ValueError('Only little-endian GGUF v2/v3 supported')
        reader.number('Q');count=reader.number('Q')
        if count>100_000:raise ValueError('Too many GGUF metadata entries')
        values={};seen=set()
        for _ in range(count):
            key=reader.string()
            if key in seen:raise ValueError('Duplicate GGUF metadata key')
            seen.add(key);values_read=reader.value(reader.number('I'),key in WANTED)
            if key in WANTED:values[key]=values_read
        metadata_end=reader.offset;metadata_hash=reader.digest.hexdigest()
        if values.get('tokenizer.ggml.model')!='gpt2':raise ValueError('Only GPT-2 byte vocabularies currently supported')
        tokens=values.get('tokenizer.ggml.tokens');types=values.get('tokenizer.ggml.token_type')
        if not isinstance(tokens,list) or not tokens or not all(isinstance(t,str) for t in tokens):raise ValueError('Missing or invalid token vocabulary')
        if not isinstance(types,list) or len(types)!=len(tokens) or not all(type(t) is int for t in types):raise ValueError('Missing or invalid token types')
        for block in iter(lambda:stream.read(1024*1024),b''):reader.digest.update(block)
        after=os.fstat(stream.fileno())
        if (before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise ValueError('Model changed during reading')
    return {'tokens':tokens,'types':types,'provenance':{'source_path':str(path.absolute()),'sha256':reader.digest.hexdigest(),
        'size_bytes':before.st_size,'metadata_prefix_bytes':metadata_end,'metadata_prefix_sha256':metadata_hash,
        'tokenizer':'gpt2','model_name':values.get('general.name'),'vocabulary_size':len(tokens),
        'association':'Operator-supplied vocabulary; session-to-model match not authenticated'}}


def decode_ids(ids,vocabulary):
    # Invert the GPT-2 reversible byte-to-Unicode alphabet.
    visible=list(range(33,127))+list(range(161,173))+list(range(174,256))
    alphabet={chr(b):b for b in visible};extra=0
    for b in range(256):
        if b not in visible:alphabet[chr(256+extra)]=b;extra+=1
    output=bytearray();special=[]
    for index,token_id in enumerate(ids):
        if type(token_id) is not int or not 0<=token_id<len(vocabulary['tokens']):raise ValueError('Token ID outside supplied vocabulary')
        token=vocabulary['tokens'][token_id];kind=vocabulary['types'][token_id]
        if kind==1:
            try:output.extend(alphabet[c] for c in token)
            except KeyError:raise ValueError('Unsupported character in GPT-2 token') from None
        elif kind in (3,4):
            special.append({'token_index':index,'token_id':token_id,'rendered_literal':token,'decoded_byte_offset':len(output)})
            output.extend(token.encode('utf-8'))
        elif kind==6 and re.fullmatch(r'<0x[0-9A-Fa-f]{2}>',token):output.append(int(token[3:5],16))
        else:raise ValueError('Unsupported token type; refusing speculative decoding')
        if len(output)>16*1024*1024:raise ValueError('Decoded output exceeds 16 MiB limit')
    # Preserve invalid/truncated UTF-8 bytes explicitly instead of silently replacing them.
    try:text=output.decode('utf-8');encoding='valid UTF-8'
    except UnicodeError:text=output.decode('utf-8',errors='backslashreplace');encoding='invalid UTF-8 bytes escaped as \\xNN'
    return {'text':text,'decoding_status':'decoded_with_supplied_vocabulary','decoded_encoding':encoding,
        'special_tokens':special,'decoded_bytes_sha256':hashlib.sha256(output).hexdigest(),
        'limitations':'Conditional on supplied vocabulary. Special tokens rendered literally. No roles, message boundaries, authorship or complete-conversation claim.'}


def decode_report(report,model):
    vocabulary=load_vocabulary(model)
    report['decoding_model']=vocabulary['provenance']
    for finding in report['findings']:
        if finding['artifact_type']!='llama_session':continue
        finding['decoding_model']=vocabulary['provenance']
        finding['limitations']=[x for x in finding['limitations'] if not x.startswith('Token IDs require')]
        finding['limitations'].append('Decoded text depends on the operator-supplied vocabulary. Session-to-model matching and remaining model state are not verified.')
        for record in finding['observations']:
            if 'token_ids' not in record:continue
            try:record.update(decode_ids(record['token_ids'],vocabulary))
            except ValueError as exc:record.update(decoding_status='unsupported',decoding_error=str(exc))
