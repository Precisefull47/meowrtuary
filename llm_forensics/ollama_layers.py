"""Resolve observed Ollama saved-message layers without trusting arbitrary paths."""
import re
from pathlib import Path

DIGEST = re.compile(r'^sha256:[0-9a-f]{64}$')
MEDIA_TYPE = 'application/vnd.ollama.image.messages'


def recover_saved_messages(report, max_bytes, inspect_file):
    root = Path(report['evidence_root'])
    recovered = {}
    for manifest in list(report['findings']):
        if manifest['artifact_type'] != 'manifest' or manifest['status'] != 'parsed':
            continue
        path = Path(manifest['source_path'])
        models = next((p for p in path.parents if p.name.lower() == 'models' and (p/'manifests') in path.parents), None)
        if models is None:
            continue
        for i, layer in enumerate(manifest['observations'][0]['layers']):
            if not isinstance(layer, dict) or layer.get('mediaType') != MEDIA_TYPE:
                continue
            digest, size = layer.get('digest'), layer.get('size')
            reference = {'manifest_path': str(path), 'record_locator': f'/layers/{i}',
                         'declared_digest': digest, 'declared_size': size}
            if not isinstance(digest, str) or not DIGEST.fullmatch(digest) or type(size) is not int or size < 0:
                report['issues'].append(dict(reference, status='invalid_layer_reference'))
                continue
            blob = models/'blobs'/digest.replace(':', '-')
            try:
                relative = blob.relative_to(root)
                # Refuse symlinks/reparse points in every component, including directories.
                current = root
                for part in relative.parts:
                    current = current/part
                    info = current.lstat()
                    if current.is_symlink() or getattr(info, 'st_file_attributes', 0) & 0x400:
                        raise ValueError('linked path is not permitted')
                if blob in recovered:
                    existing = recovered[blob]
                    if existing['size_bytes'] != size:
                        report['issues'].append(dict(reference, status='layer_size_mismatch'))
                    else:
                        existing['linked_from'].append(reference)
                    continue
                result = inspect_file(blob, 'ollama', 'saved_messages', max_bytes)
                if result['status'] not in {'size_limit', 'parse_error'}:
                    if result['sha256'] != digest[7:] or result['size_bytes'] != size or result['source_changed_during_read']:
                        result['status'] = 'layer_integrity_mismatch'
                        result['observations'] = []
                result.update(id=f"artifact-{len(report['findings'])+1}",
                              evidence_relative_path=relative.as_posix(), discovery_rule='ollama-manifest-message-link',
                              linked_from=[reference], source_profile_hint=manifest.get('source_profile_hint'))
                result['limitations'].append('Saved model messages prove stored content, not who authored it or when inference occurred. Requires an explicit saved-session artifact; not automatic API chat history.')
                report['findings'].append(result)
                recovered[blob] = result
            except (OSError, ValueError) as exc:
                report['issues'].append(dict(reference, status='linked_layer_unavailable', detail=str(exc)))
