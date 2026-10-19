"""Validate a relocated release archive on this host using synthetic evidence."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

archive = Path(sys.argv[1]).resolve()
root = Path(__file__).resolve().parents[1]
expected = archive.with_name(archive.name + '.sha256').read_text().split()[0]
assert hashlib.sha256(archive.read_bytes()).hexdigest() == expected
with tempfile.TemporaryDirectory(prefix='llmf-relocated-release-') as folder:
    with tarfile.open(archive) as bundle:
        bundle.extractall(folder, filter='data')
    stage, = Path(folder).iterdir()
    entries = (stage / 'FILES.sha256').read_text().splitlines()
    for line in entries:
        digest, relative = line.split('  ', 1)
        path = stage / relative
        assert path.resolve().is_relative_to(stage.resolve())
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest, relative
    for relative, target in json.loads((stage / 'LINKS.json').read_text()).items():
        assert str((stage / relative).readlink()) == target
        assert (stage / relative).resolve().is_relative_to(stage.resolve())
    for command in ([str(stage / 'bin/llm-forensics')], [sys.executable, str(stage / 'llm-forensics.pyz')]):
        subprocess.run([sys.executable, str(root / 'smoke_cli.py'), *command], check=True)
    print(json.dumps({'passed': True, 'archive_sha256': expected,
        'regular_files_verified': len(entries), 'scope': 'Relocated archive on the build host; not a separate clean Mac'}))
