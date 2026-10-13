import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from llm_forensics.token_decode import load_vocabulary,decode_ids,decode_report
from llm_forensics.scanner import scan


def string(value):
    data=value.encode();return struct.pack('<Q',len(data))+data


def model_bytes(tokenizer='gpt2',tokens=None,types=None):
    tokens=tokens or ['Hello','Ġworld','Ã','©','<|end|>']
    types=types or [1,1,1,1,3]
    entries=[string('tokenizer.ggml.model')+struct.pack('<I',8)+string(tokenizer),
             string('tokenizer.ggml.tokens')+struct.pack('<IIQ',9,8,len(tokens))+b''.join(string(x) for x in tokens),
             string('tokenizer.ggml.token_type')+struct.pack('<IIQ',9,5,len(types))+struct.pack('<'+str(len(types))+'i',*types)]
    return b'GGUF'+struct.pack('<IQQ',3,0,len(entries))+b''.join(entries)


class TokenDecodeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.model=self.root/'vocab.gguf';self.model.write_bytes(model_bytes())
    def tearDown(self):self.temp.cleanup()
    def test_unicode_across_tokens_and_special_literal(self):
        v=load_vocabulary(self.model)
        result=decode_ids([0,1,2,3,4],v)
        self.assertEqual(result['text'],'Hello worldé<|end|>')
        self.assertEqual(result['special_tokens'][0]['token_index'],4)
        self.assertEqual(result['special_tokens'][0]['decoded_byte_offset'],13)
        self.assertEqual(v['provenance']['sha256'],hashlib.sha256(self.model.read_bytes()).hexdigest())
    def test_partial_unicode_is_explicit(self):
        r=decode_ids([2],load_vocabulary(self.model))
        self.assertEqual(r['text'],'\\xc3')
        self.assertIn('invalid',r['decoded_encoding'])
    def test_ids_outside_vocab_and_unknown_types_rejected(self):
        v=load_vocabulary(self.model)
        for ids in ([-1],[999],[True]):
            with self.assertRaises(ValueError):decode_ids(ids,v)
        v['types'][0]=2
        with self.assertRaises(ValueError):decode_ids([0],v)
    def test_unsupported_tokenizer_and_truncation_rejected(self):
        for data in (model_bytes(tokenizer='llama'),model_bytes()[:-1],b'GGUF'+struct.pack('<IQQ',3,0,1)+struct.pack('<Q',2**63)):
            self.model.write_bytes(data)
            with self.assertRaises(ValueError):load_vocabulary(self.model)
    def test_token_type_count_must_match(self):
        self.model.write_bytes(model_bytes(types=[1]))
        with self.assertRaises(ValueError):load_vocabulary(self.model)
    def test_same_ids_wrong_vocab_not_claimed_authenticated(self):
        self.model.write_bytes(model_bytes(tokens=['Other','Ġtext'],types=[1,1]))
        v=load_vocabulary(self.model)
        self.assertEqual(decode_ids([0,1],v)['text'],'Other text')
        self.assertIn('not authenticated',v['provenance']['association'])
    def test_cli_exports_and_preserves_sources(self):
        evidence=self.root/'evidence';evidence.mkdir();cache=evidence/'session.cache'
        cache.write_bytes(b'nsgg'+struct.pack('<II2i',10,2,0,1)+b'opaque state')
        originals=(cache.read_bytes(),self.model.read_bytes())
        output=self.root/'report'
        r=subprocess.run([sys.executable,'-m','llm_forensics',str(evidence),'--decode-model',str(self.model),'--output',str(output),'--format','both'],capture_output=True,text=True)
        self.assertEqual(r.returncode,0,r.stderr)
        result=json.loads((output/'decoded-sessions.json').read_text())
        self.assertEqual(result['records'][0]['text'],'Hello world')
        self.assertNotIn('role',result['records'][0])
        self.assertIn('Supplied decoding model',(output/'report.html').read_text())
        self.assertEqual(originals,(cache.read_bytes(),self.model.read_bytes()))
    def test_incompatible_session_keeps_token_evidence(self):
        evidence=self.root/'evidence';evidence.mkdir()
        (evidence/'session.cache').write_bytes(b'nsgg'+struct.pack('<IIi',10,1,999)+b'state')
        report=scan(evidence);decode_report(report,self.model)
        record=report['findings'][0]['observations'][0]
        self.assertEqual(record['token_ids'],[999])
        self.assertEqual(record['decoding_status'],'unsupported')
        self.assertNotIn('text',record)
