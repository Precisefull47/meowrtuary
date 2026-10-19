"""Package the local macOS ARM64 validation bundle using an explicit allowlist."""
import hashlib
import json
from pathlib import Path
import platform
import shutil
import tarfile
import tempfile
from datetime import datetime, timezone
from llm_forensics import __version__

ROOT = Path(__file__).resolve().parent
DOCS = ('SUPPORTED_USE.md', 'README.md', 'USER_GUIDE.md', 'VALIDATION.md', 'RELEASE_NOTES.md')


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def main():
    if (platform.system(), platform.machine()) != ('Darwin', 'arm64'):
        raise SystemExit('This release builder requires the macOS ARM64 build host.')
    native = ROOT / 'dist/darwin-arm64/llm-forensics'
    portable = ROOT / 'dist/llm-forensics.pyz'
    if not (native / 'llm-forensics').is_file() or not portable.is_file():
        raise SystemExit('Build the native bundle and portable archive first.')
    destination = ROOT / 'dist/releases'
    destination.mkdir(parents=True, exist_ok=True)
    name = f'llm-forensics-{__version__}-macos-arm64'
    archive = destination / f'{name}.tar.gz'
    if archive.exists() or archive.with_name(archive.name+'.sha256').exists():
        raise FileExistsError('Release already exists; preserve it and choose a new version.')
    with tempfile.TemporaryDirectory(prefix='llmf-release-') as folder:
        stage = Path(folder) / name
        stage.mkdir()
        shutil.copytree(native, stage / 'bin', symlinks=True)
        (stage/'VERSION').write_text(__version__+'\n')
        shutil.copy2(ROOT/'packaging/install-local.sh',stage/'install-local.sh')
        (stage/'install-local.sh').chmod(0o755)
        shutil.copy2(portable, stage / portable.name)
        source_dir=stage/'source/llm_forensics';source_dir.mkdir(parents=True)
        for module in (ROOT/'llm_forensics').glob('*.py'):
            if module.is_symlink():raise ValueError('Source module links are not distributable')
            shutil.copy2(module,source_dir/module.name)
        for filename in ('pyproject.toml','build_cli.py','build_native.py','build_release.py','cli_entry.py','smoke_cli.py','build-requirements.txt'):
            shutil.copy2(ROOT/filename,stage/'source'/filename)
        shutil.copytree(ROOT/'packaging',stage/'source/packaging',ignore=shutil.ignore_patterns('__pycache__'))
        for doc in DOCS:
            shutil.copy2(ROOT / doc, stage / doc)
            shutil.copy2(ROOT / doc, stage / 'source' / doc)
        (stage / 'RELEASE.json').write_text(json.dumps({
            'version': __version__, 'scope': 'Local macOS Apple Silicon validation bundle',
            'built_at_utc': datetime.now(timezone.utc).isoformat(),
            'host': platform.platform(), 'python_builder': platform.python_version(),
            'source_sha256':{p.name:digest(p) for p in sorted(source_dir.glob('*.py'))},
            'build_requirements':(ROOT/'build-requirements.txt').read_text().splitlines(),
            'developer_id_signed': False, 'notarized': False,
            'limitations': 'Same-host validation only; no Intel, older macOS or clean-machine certification. Hashes are not signatures.',
        }, indent=2) + '\n')
        hashes = []
        links = {}
        for entry in sorted(stage.rglob('*')):
            relative = entry.relative_to(stage).as_posix()
            if entry.is_symlink():
                if not entry.resolve(strict=True).is_relative_to(stage.resolve()):
                    raise RuntimeError(f'Link escapes release: {relative}')
                links[relative] = str(entry.readlink())
            elif entry.is_file():
                hashes.append(f'{digest(entry)}  {relative}\n')
        (stage / 'LINKS.json').write_text(json.dumps(links, indent=2) + '\n')
        hashes.append(f'{digest(stage / "LINKS.json")}  LINKS.json\n')
        (stage / 'FILES.sha256').write_text(''.join(hashes))
        with tarfile.open(archive, 'x:gz') as output:
            output.add(stage, arcname=name)
    checksum = archive.with_name(archive.name + '.sha256')
    checksum.write_text(f'{digest(archive)}  {archive.name}\n')
    print(archive)
    print(checksum)


if __name__ == '__main__':
    main()
