import struct,tempfile,unittest
from pathlib import Path
from llm_forensics.llama_artifacts import inspect_llama
from llm_forensics.scanner import scan


class LlamaArtifactsTests(unittest.TestCase):
    def test_session_token_provenance(self):
        data=b'nsgg'+struct.pack('<II3i',10,3,1,24,55)+b'opaque state'
        result=inspect_llama(data)
        self.assertEqual(result['status'],'partial')
        row=result['observations'][0]
        self.assertEqual(row['token_ids'],[1,24,55])
        self.assertEqual(row['token_byte_offset'],12)
        self.assertNotIn('text',row)
    def test_malformed_session_and_unknown_version(self):
        for data,status in [(b'nsgg','invalid_header'),(b'nsgg'+struct.pack('<II',99,0),'unsupported_version'),(b'nsgg'+struct.pack('<II',10,100),'invalid_structure'),(b'nsgg'+struct.pack('<IIi',10,1,-1)+b'x','invalid_structure')]:
            self.assertEqual(inspect_llama(data)['status'],status)
    def test_log_offsets_and_no_fabricated_roles(self):
        data='0.00.001.123 I llama_completion: llama backend init\nhello café\n'.encode()
        result=inspect_llama(data)
        row=result['observations'][1]
        self.assertEqual(data[row['byte_offset']:].decode().strip(),row['text'])
        self.assertNotIn('role',row)
        self.assertIsNone(inspect_llama(b'unrelated log'))
    def test_scanner_signature_and_negative_controls(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'random-name.cache').write_bytes(b'nsgg'+struct.pack('<IIi',10,1,17)+b'state')
            (root/'other.log').write_text('not a runner log')
            (root/'other.bin').write_bytes(b'not a runner cache')
            report=scan(root)
            self.assertEqual(len(report['findings']),1)
            self.assertEqual(report['findings'][0]['artifact_type'],'llama_session')
            self.assertEqual(report['findings'][0]['runner'],'llama_cpp')
