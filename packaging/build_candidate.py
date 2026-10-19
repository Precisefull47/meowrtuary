"""Create a clean, immutable meowrtuary distribution archive."""
import hashlib,json,shutil,subprocess,tarfile,tempfile
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from llm_forensics import __version__

def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    native=ROOT/'dist/darwin-arm64/llm-forensics'
    result=subprocess.check_output([str(native/'llm-forensics'),'--version'],text=True)
    if result.strip().split()[-1]!=__version__:raise ValueError('Rebuild the native version before packaging')
    out=ROOT/'dist/distribution';out.mkdir(exist_ok=True)
    name=f'meowrtuary-{__version__}-macos-arm64'
    archive=out/(name+'.tar.gz')
    if archive.exists():raise FileExistsError('Preserve existing candidate; choose a new version or archive it manually')
    with tempfile.TemporaryDirectory() as temp:
        stage=Path(temp)/name;stage.mkdir()
        shutil.copytree(native,stage/'bin',symlinks=True)
        for name_ in ('README.md','THIRD_PARTY_NOTICES.md','SUPPORTED_USE.md','RELEASE_NOTES.md','USER_GUIDE.md','VALIDATION.md'):
            shutil.copyfile(ROOT/'packaging/release-docs'/name_,stage/name_)
        shutil.copyfile(ROOT/'LICENSE',stage/'LICENSE')
        shutil.copytree(ROOT/'packaging/licenses',stage/'licenses')
        shutil.copyfile(ROOT/'packaging/install-local.sh',stage/'install-local.sh')
        (stage/'install-local.sh').chmod(0o755)
        (stage/'VERSION').write_text(__version__+'\n')
        (stage/'RELEASE.json').write_text(json.dumps({'product':'meowrtuary','version':__version__,'label':__version__,'platform':'macOS ARM64','developer_id_signed':False,'notarized':False,'independent_mac_verified':False},indent=2)+'\n')
        hashes=[];links={}
        for p in sorted(stage.rglob('*')):
            rel=p.relative_to(stage).as_posix()
            if p.is_symlink():
                if not p.resolve().is_relative_to(stage.resolve()):raise ValueError('Escaping symlink')
                links[rel]=str(p.readlink())
            elif p.is_file():hashes.append(f'{digest(p)}  {rel}\n')
        (stage/'LINKS.json').write_text(json.dumps(links,indent=2)+'\n')
        hashes.append(f'{digest(stage/"LINKS.json")}  LINKS.json\n')
        (stage/'FILES.sha256').write_text(''.join(hashes))
        # Omit developer usernames, UID/GID, and metadata from archive headers.
        def clean(info):
            info.uid=info.gid=0;info.uname=info.gname='';info.pax_headers={};return info
        with tarfile.open(archive,'x:gz') as tar:tar.add(stage,arcname=name,filter=clean)
    Path(str(archive)+'.sha256').write_text(f'{digest(archive)}  {archive.name}\n')
    print(archive)
if __name__=='__main__':main()
