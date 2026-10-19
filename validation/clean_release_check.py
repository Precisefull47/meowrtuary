"""Release-only acceptance in temporary HOME/TMPDIR/cwd and a pip-free venv.

No real user profile scans. This is same-host isolation, not a clean OS/account.
"""
import hashlib,json,os,platform,shutil,subprocess,sys,tarfile,tempfile,time,venv,zipfile,re
from pathlib import Path


def run(archive, output):
    archive=Path(archive).resolve();output=Path(output).resolve()
    if output.exists():raise ValueError('Result already exists')
    expected=archive.with_name(archive.name+'.sha256').read_text().split()[0]
    assert hashlib.sha256(archive.read_bytes()).hexdigest()==expected
    checks=[];started=time.monotonic()
    with tempfile.TemporaryDirectory(prefix='llmf-clean-') as temp:
        base=Path(temp).resolve();home=base/'home';home.mkdir();tmp=base/'tmp';tmp.mkdir();cwd=base/'unrelated working directory';cwd.mkdir()
        env={'HOME':str(home),'TMPDIR':str(tmp),'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'en_US.UTF-8','LC_ALL':'en_US.UTF-8','TERM':'dumb','PYTHONNOUSERSITE':'1'}
        with tarfile.open(archive) as bundle:bundle.extractall(base/'unpacked',filter='data')
        stage,=(base/'unpacked').iterdir()
        listed=set()
        for line in (stage/'FILES.sha256').read_text().splitlines():
            digest,rel=line.split('  ',1);p=stage/rel;assert p.resolve().is_relative_to(stage.resolve())
            assert hashlib.sha256(p.read_bytes()).hexdigest()==digest;listed.add(rel)
        links=json.loads((stage/'LINKS.json').read_text())
        for rel,target in links.items():
            assert str((stage/rel).readlink())==target
            assert (stage/rel).resolve().is_relative_to(stage.resolve())
        actual={p.relative_to(stage).as_posix() for p in stage.rglob('*') if p.is_file() and not p.is_symlink()}
        assert actual==listed|{'FILES.sha256'}
        assert os.access(stage/'bin/llm-forensics',os.X_OK)
        forbidden=[]
        secret_re=re.compile(rb'(?:sk-(?:proj-)?[A-Za-z0-9_-]{32,}|gh[pousr]_[A-Za-z0-9]{30,}|AKIA[A-Z0-9]{16}|-----BEGIN (?:EC |OPENSSH |DSA )?PRIVATE KEY-----)')
        patterns=(b'/Users/kyu/',b'g-p-6ab8fc190498819186939bfde2f50c3b',b'-----BEGIN PRIVATE KEY-----',b'-----BEGIN RSA PRIVATE KEY-----')
        for p in stage.rglob('*'):
            if not p.is_file() or p.is_symlink():continue
            raw=p.read_bytes()
            if any(x in raw for x in patterns) or secret_re.search(raw):forbidden.append(str(p.relative_to(stage)))
            assert not any(x in p.relative_to(stage).parts for x in ('cases','runner-lab','.venv-build'))
        with zipfile.ZipFile(stage/'llm-forensics.pyz') as z:
            for name in z.namelist():
                if not name.endswith('/'):assert name.endswith('.py'),name
                assert not any(x in z.read(name) for x in patterns) and not secret_re.search(z.read(name)),name
        assert not forbidden,forbidden
        checks.append({'name':'archive hashes, membership, permissions, private-path/key scan','passed':True,'files':len(listed)})
        environment=base/'fresh-venv';venv.EnvBuilder(with_pip=False,system_site_packages=False).create(environment)
        python=environment/'bin/python'
        def call(command,args,code=0):
            p=subprocess.run([*map(str,command),*map(str,args)],cwd=cwd,env=env,capture_output=True,text=True,timeout=90)
            if p.returncode!=code or 'Traceback' in p.stderr:raise AssertionError((args,p.returncode,p.stdout[-1500:],p.stderr[-1500:]))
            return p
        launchers={'native':[stage/'bin/llm-forensics'],'portable':[python,'-I','-S',stage/'llm-forensics.pyz']}
        for label,command in launchers.items():
            call(command,['--help']);call(command,['--version']);doctor=json.loads(call(command,['--doctor']).stdout);assert doctor['passed']
            call(command,['--self-test','--output',base/(label+'-kit')]);assert json.loads((base/(label+'-kit')/'validation-results.json').read_text())['passed']
            # Harness shipped with the release, running from unrelated cwd.
            call([python,stage/'source/smoke_cli.py'],command)
            checks.append({'name':label+' release-only workflow smoke and synthetic kit','passed':True,'doctor':doctor})
            evidence=base/(label+' evidence ü')/'.ollama';evidence.mkdir(parents=True);source=evidence/'history';source.write_bytes(b'CONTROLLED_NEW_USER\n')
            old=hashlib.sha256(source.read_bytes()).hexdigest();case=base/(label+' case ü')
            call(command,[evidence,'--source-os','macos','--acquire','--timeline','--format','both','--export-conversations','--strict','--output',case])
            assert hashlib.sha256(source.read_bytes()).hexdigest()==old
            call(command,['--verify-case',case]);call(command,['--verify-package',case])
            bundle=base/(label+' bundle');call(command,['--bundle-case',case,'--output',bundle])
            tarpath=bundle/'case.tar.gz';hashvalue=hashlib.sha256(tarpath.read_bytes()).hexdigest()
            assert hashvalue==tarpath.with_name('case.tar.gz.sha256').read_text().split()[0]
            with tarfile.open(tarpath) as tar:tar.extractall(base/(label+' reopened'),filter='data')
            call(command,['--verify-package',base/(label+' reopened/case')])
            damaged=bytearray(tarpath.read_bytes());damaged[len(damaged)//2]^=1
            assert hashlib.sha256(damaged).hexdigest()!=hashvalue
            checks.append({'name':label+' unicode capture, hashes, bundle, extraction, reopen, bundle corruption checksum','passed':True})
            for name,args,code in [
                ('missing',[base/'absent','--output',base/(label+' missing')],1),
                ('existing',[evidence,'--output',case],2),
                ('empty-path',['','--output',base/(label+' empty-path')],2),
                ('bad-limit',[evidence,'--max-file-mb','0','--output',base/(label+' limit')],2),
                ('conflict',['--verify-case',case,'--timeline'],2),
                ('unknown',['--unknown-option'],2),
                ('missing-manifest',['--verify-package',cwd],1)]:
                call(command,args,code);checks.append({'name':label+' negative '+name,'passed':True})
            empty=base/(label+' empty');empty.mkdir();call(command,[empty,'--strict','--output',base/(label+' empty-result')])
            link=base/(label+' broken');link.symlink_to(base/'absent');call(command,[link,'--output',base/(label+' linked-result')],1)
            corrupt=base/(label+' corrupt/Library/Application Support/Ollama/db.sqlite');corrupt.parent.mkdir(parents=True);corrupt.write_bytes(b'not SQLite')
            call(command,[corrupt,'--strict','--output',base/(label+' corrupt-result')],3)
            malformed=base/(label+' malformed/.lmstudio/conversations/x.json');malformed.parent.mkdir(parents=True)
            for i,raw in enumerate((b'{bad',b'{"role":"user","content":"a","content":"b"}',b'{"unknown":[]}')):
                malformed.write_bytes(raw);call(command,[malformed,'--strict','--output',base/(label+f' malformed-{i}')],3)
            (case/'unexpected').write_text('extra');call(command,['--verify-package',case],1);(case/'unexpected').unlink()
            m=json.loads((case/'acquisition-manifest.json').read_text());(case/m['files'][0]['case_path']).write_text('tampered')
            call(command,['--verify-case',case],1);call(command,['--verify-package',case],1);call(command,['--bundle-case',case,'--output',base/(label+' refused-bundle')],1)
            checks.append({'name':label+' empty, links, malformed/unsupported input, tamper and bundle refusal','passed':True})
        # Source as shipped, without checkout imports or third-party packages.
        source_command=[python,'-I','-S','-c',"import runpy,sys;sys.path.insert(0,sys.argv.pop(1));runpy.run_module('llm_forensics',run_name='__main__')",stage/'source']
        assert json.loads(call(source_command,['--doctor']).stdout)['passed']
        call(source_command,['--self-test','--output',base/'source-kit'])
        assert json.loads((base/'source-kit/validation-results.json').read_text())['passed']
        checks.append({'name':'shipped source in pip-free venv with isolated imports','passed':True})
        # No named temporary DB directories or pending seal files survive commands.
        assert not list(tmp.iterdir()),list(tmp.iterdir())
        checks.append({'name':'temporary runtime directory cleaned','passed':True})
    result={'passed':True,'archive_sha256':expected,'checks':checks,'check_count':len(checks),'host':platform.platform(),'python':sys.version,'elapsed_seconds':round(time.monotonic()-started,3),'scope':'Same account/OS/kernel; temporary HOME/TMPDIR, minimal environment, unrelated cwd, pip-free venv, release-only files. Not independent Mac, fresh account, VM or Gatekeeper certification.'}
    output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'passed':True,'checks':len(checks),'output':str(output)}))

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive',type=Path)
    parser.add_argument('output',type=Path)
    args=parser.parse_args()
    run(args.archive,args.output)
