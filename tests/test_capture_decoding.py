import hashlib
import struct
import tempfile
import unittest
from pathlib import Path
from llm_forensics.acquisition import acquire, verify_case
from llm_forensics.scanner import inspect_file, scan


class CaptureDecodingTests(unittest.TestCase):
    def test_model_blob_prefix_and_unknown_blob_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = root / '.ollama'
            blobs = source / 'models/blobs'
            blobs.mkdir(parents=True)
            header = b'GGUF' + struct.pack('<IQQ', 3, 12, 4)
            (blobs / 'sha256-model-partial').write_bytes(header + bytes(4096))
            (blobs / 'sha256-unknown').write_bytes(b'unknown' * 100)
            case = root / 'case'
            manifest = acquire([(source, '.ollama')], case, 'macos', 128)
            self.assertEqual(len(manifest['files']), 1)
            entry = manifest['files'][0]
            self.assertEqual(entry['capture_mode'], 'prefix')
            self.assertEqual(entry['source_size_bytes'], 4120)
            self.assertEqual(entry['size_bytes'], 24)
            self.assertEqual(entry['sha256'], hashlib.sha256(header).hexdigest())
            self.assertEqual(manifest['issues'][0]['detail'], 'size_limit')
            finding = scan(case / 'evidence', source_os='macos')['findings'][0]
            self.assertEqual(finding['status'], 'header_only')
            self.assertEqual(finding['artifact_type'], 'gguf_header')
            self.assertTrue(verify_case(case)['verified'])

    def test_zsh_meta_decoding_preserves_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / '.zsh_history'
            original = 'llama-cli -p "☃"\n'.encode()
            encoded = b''.join(bytes((0x83, b ^ 32)) if b == 0 or 0x83 <= b <= 0xa2 else bytes((b,)) for b in original)
            p.write_bytes(encoded)
            finding = inspect_file(p, 'llama_cpp', 'shell_history', 8192)
            self.assertEqual(finding['status'], 'parsed')
            self.assertEqual(finding['observations'][0]['text'], original.decode().strip())
            self.assertEqual(finding['sha256'], hashlib.sha256(encoded).hexdigest())
            self.assertEqual(p.read_bytes(), encoded)
            self.assertGreater(finding['text_decoding']['meta_pairs'], 0)

    def test_plain_utf8_and_invalid_encoding(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / '.zsh_history'
            p.write_text('llama-cli -p "☃"\n')
            self.assertNotIn('text_decoding', inspect_file(p, 'llama_cpp', 'shell_history', 8192))
            for data in (b'llama-cli\x83', b'llama-cli\x83*', b'llama-cli\xff'):
                p.write_bytes(data)
                self.assertEqual(inspect_file(p, 'llama_cpp', 'shell_history', 8192)['status'], 'parse_error')
            other = Path(tmp) / '.bash_history'
            other.write_bytes(b'llama-cli\x83\xa3')
            self.assertEqual(inspect_file(other, 'llama_cpp', 'shell_history', 8192)['status'], 'parse_error')
