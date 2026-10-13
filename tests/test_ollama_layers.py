import hashlib,json,tempfile,unittest
from pathlib import Path
from llm_forensics.scanner import scan

class SavedLayerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.models=self.root/'.ollama/models'
        self.blobs=self.models/'blobs';self.blobs.mkdir(parents=True)
        self.manifest=self.models/'manifests/registry.ollama.ai/library/saved/latest'
        self.manifest.parent.mkdir(parents=True)
        self.data=json.dumps([{'role':'user','content':'test prompt'},{'role':'assistant','content':'test answer'}]).encode()
        self.digest=hashlib.sha256(self.data).hexdigest()
        self.blob=self.blobs/('sha256-'+self.digest);self.blob.write_bytes(self.data)
        self.write_manifest('sha256:'+self.digest,len(self.data))
    def tearDown(self):self.temp.cleanup()
    def write_manifest(self,digest,size):
        self.manifest.write_text(json.dumps({'layers':[{'mediaType':'application/vnd.ollama.image.messages','digest':digest,'size':size}]}))
    def saved(self):return [f for f in scan(self.root)['findings'] if f['artifact_type']=='saved_messages']
    def test_verified_content_and_provenance(self):
        f=self.saved()[0]
        self.assertEqual(f['status'],'parsed');self.assertEqual(len(f['observations']),2)
        self.assertEqual(f['observations'][1]['record_locator'],'/1/content')
        self.assertEqual(f['linked_from'][0]['record_locator'],'/layers/0')
    def test_tampered_content_never_exported(self):
        self.blob.write_bytes(self.data.replace(b'answer',b'forged'))
        f=self.saved()[0];self.assertEqual(f['status'],'layer_integrity_mismatch');self.assertEqual(f['observations'],[])
    def test_size_mismatch(self):
        self.write_manifest('sha256:'+self.digest,1)
        self.assertEqual(self.saved()[0]['status'],'layer_integrity_mismatch')
    def test_missing_blob_is_visible(self):
        self.blob.unlink();r=scan(self.root)
        self.assertEqual(r['issues'][0]['status'],'linked_layer_unavailable')
    def test_digest_traversal_rejected(self):
        self.write_manifest('../../outside',1)
        self.assertEqual(scan(self.root)['issues'][0]['status'],'invalid_layer_reference')
    def test_symlink_blob_rejected(self):
        self.blob.unlink()
        outside=self.root/'elsewhere';outside.write_bytes(self.data)
        try:self.blob.symlink_to(outside)
        except OSError:self.skipTest('Symlinks unavailable')
        self.assertEqual(self.saved(),[])
    def test_bounded_blob_read(self):
        r=scan(self.root,max_bytes=1)
        self.assertTrue(all(f['status']=='size_limit' for f in r['findings']))
    def test_oversized_linked_layer_reported(self):
        data=json.dumps([{'role':'user','content':'x'*2000}]).encode()
        digest=hashlib.sha256(data).hexdigest()
        (self.blobs/('sha256-'+digest)).write_bytes(data)
        self.write_manifest('sha256:'+digest,len(data))
        r=scan(self.root,max_bytes=1024)
        self.assertEqual([f for f in r['findings'] if f['artifact_type']=='saved_messages'][0]['status'],'size_limit')
    def test_malformed_role_does_not_crash(self):
        data=b'[{"role":[],"content":"bad"}]'
        digest=hashlib.sha256(data).hexdigest()
        (self.blobs/('sha256-'+digest)).write_bytes(data)
        self.write_manifest('sha256:'+digest,len(data))
        self.assertEqual(self.saved()[0]['status'],'unsupported_schema')
