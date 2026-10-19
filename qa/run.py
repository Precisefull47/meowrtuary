#!/usr/bin/env python3
"""Isolated macOS QA: one command, fresh candidate, durable evidence, no publishing."""
import argparse,contextlib,fcntl,hashlib,json,os,platform,shutil,signal,subprocess,sys,tarfile,time,uuid
from datetime import datetime,timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
STATE=ROOT/'qa/state'
RUNS=ROOT/'qa/runs'
MANDATORY_EXTERNAL={
 'actual_gui':'Native file/folder selection, cancellation, report/Finder/settings opening and terminal visual acceptance on this exact candidate.',
 'real_runner':'Versioned controlled conversations from Ollama, LM Studio and llama.cpp; fixture tests are not real-runner evidence.',
 'independent_mac':'Installation and examiner workflow on another physical Apple Silicon Mac; same-host isolation and hosted CI are distinct.'}

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()

def write_json(path,data):
    with path.open('x') as f:json.dump(data,f,indent=2)

def source_files(source):
    paths=list(source.glob('*.py'))+list(source.glob('*.md'))
    paths += [source/name for name in ('pyproject.toml','build-requirements.txt','.gitignore','LICENSE') if (source/name).exists()]
    for folder,pattern in [('llm_forensics','*.py'),('tests','*.py'),('validation','*.py')]:paths+=list((source/folder).glob(pattern))
    for folder,patterns in [('qa',('*.py','*.md','*.json')),('qa/tests',('*.py',)),('.github/workflows',('*.yml','*.yaml'))]:
        for pattern in patterns:paths+=list((source/folder).glob(pattern))
    # Distribution inputs only: never recursively capture arbitrary packaging data.
    for folder,patterns in [('packaging',('*.py','*.sh','*.md')),
                            ('packaging/licenses',('*.txt',)),
                            ('packaging/release-docs',('*.md',)),
                            ('packaging/homebrew-meowrtuary',('README.md','LICENSE')),
                            ('packaging/homebrew-meowrtuary/Formula',('*.rb',))]:
        for pattern in patterns:paths+=list((source/folder).glob(pattern))
    for p in paths:
        if p.is_symlink() or any(parent.is_symlink() for parent in p.parents if parent!=source.parent):raise ValueError('Source links are not allowed: '+str(p))
    return sorted(set(paths))

def snapshot(source):
    files=source_files(source)
    if not (source/'llm_forensics/__main__.py') in files:raise ValueError('Not a product source tree')
    hashes={p.relative_to(source).as_posix():digest(p) for p in files}
    token=hashlib.sha256(json.dumps(hashes,sort_keys=True).encode()).hexdigest()
    return files,hashes,token

@contextlib.contextmanager
def locked(path):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('a') as f:
        fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
        try:yield
        finally:fcntl.flock(f,fcntl.LOCK_UN)

def git(repo,*args):
    return subprocess.run(['git','-c','user.name=Local QA','-c','user.email=qa@localhost','-c','commit.gpgsign=false',*args],cwd=repo,check=True,capture_output=True,text=True).stdout.strip()

def workspace(source,run_id,files,hashes):
    # This private repository has no remote and never touches a product main branch.
    repo=STATE/'repository';repo.mkdir(parents=True,exist_ok=True)
    if not (repo/'.git').exists():git(repo,'init','-b','qa-baseline')
    if git(repo,'remote'):raise ValueError('Private QA repository must have no remotes')
    if git(repo,'branch','--show-current')!='qa-baseline':raise ValueError('Unexpected QA baseline branch')
    tracked=git(repo,'ls-files').splitlines()
    for name in tracked:
        if name not in hashes:(repo/name).unlink()
    for p in files:
        out=repo/p.relative_to(source);out.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,out)
        if digest(out)!=hashes[p.relative_to(source).as_posix()]:raise ValueError('Source changed while taking snapshot')
    git(repo,'add','-u')
    git(repo,'add','-f','--',*hashes.keys())
    if git(repo,'status','--porcelain'):git(repo,'commit','-m','QA input snapshot '+run_id)
    work=STATE/'worktrees'/run_id;work.parent.mkdir(parents=True,exist_ok=True)
    git(repo,'worktree','add','-b','qa/'+run_id,str(work),'HEAD')
    return work,git(repo,'rev-parse','HEAD')

def stop_owned_tree(process):
    """Always stop the owned group; enumerate detached descendants when permitted."""
    if process.poll() is not None:return 'already_exited'
    owned=[];scope='process_group_only'
    try:
        listing=subprocess.run(['/bin/ps','-axo','pid=,ppid='],capture_output=True,text=True,timeout=5)
        if listing.returncode==0:
            parents={int(parts[0]):int(parts[1]) for line in listing.stdout.splitlines() if len(parts:=line.split())==2}
            owned=[process.pid]
            for parent in owned:owned.extend(pid for pid,ppid in parents.items() if ppid==parent and pid not in owned)
            scope='observed_descendants_and_process_group'
    except (OSError,subprocess.TimeoutExpired):pass
    # No broad process-name killing. Only this spawned group and observed child PIDs.
    for pid in reversed(owned):
        if pid==process.pid:continue
        try:os.kill(pid,signal.SIGKILL)
        except ProcessLookupError:pass
    try:os.killpg(process.pid,signal.SIGKILL)
    except ProcessLookupError:pass
    process.wait(timeout=5)
    return scope


def execute(command,cwd,env,log,timeout):
    start=time.monotonic();cleanup_scope=None
    with log.open('xb') as output:
        p=subprocess.Popen(list(map(str,command)),cwd=cwd,env=env,stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
        try:code=p.wait(timeout=timeout);timed_out=False
        except (subprocess.TimeoutExpired,KeyboardInterrupt) as exc:
            cleanup_scope=stop_owned_tree(p)
            if isinstance(exc,KeyboardInterrupt):raise
            code=124;timed_out=True
    return {'exit_code':code,'timed_out':timed_out,'seconds':round(time.monotonic()-start,3),'log':str(log),'cleanup_scope':cleanup_scope}

def assess(rows,full=True):
    automatic=[r for r in rows if r['category'] not in MANDATORY_EXTERNAL]
    passed=full and bool(automatic) and all(r['status']=='PASS' for r in automatic)
    ready=passed and set(MANDATORY_EXTERNAL).issubset({r['category'] for r in rows}) and all(r['status']=='PASS' for r in rows)
    return passed,ready,'READY FOR DOCUMENTED DEPLOYMENT' if ready else 'NOT READY — acceptance gates outstanding'

def render(report):
    lines=['# Local LLM Forensics — deployment readiness', '', 'Run: '+report['run_id'],'', '**'+report['verdict']+'**','',
           'Automated gate: '+('PASS' if report['automated_passed'] else 'INCOMPLETE / FAILED'),
           'Production readiness: NOT CLAIMED. External acceptance gates remain separate.','',
           'Candidate workspace: `'+report.get('workspace','not created')+'`','',
           '| Check | Category | Status | Severity | Detail |','|---|---|---|---|---|']
    for r in report['checks']:lines.append('| '+' | '.join(str(r.get(k,'')).replace('|','/').replace('\n',' ') for k in ('id','category','status','severity','detail'))+' |')
    lines+=['','## Fixes and remaining blockers','', 'No autonomous merge or publication is performed. Proposed repairs are tracked in repair events and retained in isolated branches. Historical acceptance is not inherited by a new candidate.','',
            'Logs and per-test results accompany this report. GUI adapters are simulated; PTYs execute the real CLI but do not certify native dialogs. Hosted CI is not a second physical Mac.']
    if report.get('fixes_applied'):
        lines+=['','## Verified QA repair history','']+['- '+note for note in report['fixes_applied']]
    return '\n'.join(lines)+'\n'

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,default=ROOT)
    p.add_argument('--build-python',type=Path)
    p.add_argument('--only',action='append',help='Check ID; selected tests plus builds. Partial runs never pass readiness.')
    p.add_argument('--allow-missing-external',action='store_true',help='Exit 0 for an automated pass; missing external gates still prevent readiness.')
    p.add_argument('--campaign',type=Path,help='Original report.json for a repair chain; preserves defect budget identity.')
    a=p.parse_args();source=a.source.resolve(strict=True)
    run_id=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8]
    RUNS.mkdir(parents=True,exist_ok=True);out=RUNS/run_id;out.mkdir();(out/'logs').mkdir()
    report={'schema_version':1,'run_id':run_id,'started_utc':datetime.now(timezone.utc).isoformat(),'host':platform.platform(),'architecture':platform.machine(),
            'source':str(source),'checks':[],'fixes_applied':[],'publication':'disabled','merge':'disabled','max_repairs_per_failure':3}
    rows=report['checks'];automatic=False;ready=False;deadline=time.monotonic()+1800
    try:
      with locked(STATE/'run.lock'):
        files,hashes,token=snapshot(source);report['source_sha256']=token
        report['campaign']=json.loads(a.campaign.read_text())['campaign'] if a.campaign else token
        write_json(out/'source-manifest.json',hashes)
        work,commit=workspace(source,run_id,files,hashes);report.update(workspace=str(work),baseline_commit=commit)
        # Metadata inventory only: never open original cases or historical captured evidence.
        inventory=[{'path':str(f.relative_to(source)),'bytes':f.stat().st_size} for f in source.glob('validation/*') if f.is_file() and not f.is_symlink()]
        write_json(out/'validation-record-inventory.json',inventory)
        home=out/'home';tmp=out/'tmp';home.mkdir();tmp.mkdir()
        env={**os.environ,'HOME':str(home),'TMPDIR':str(tmp),'PYTHONNOUSERSITE':'1','PYTHONDONTWRITEBYTECODE':'1','TERM':'dumb','NO_COLOR':'1'}
        for key in ('PYTHONPATH','PYTHONHOME','LLMF_SELECTED_OUTPUT','OLLAMA_MODELS','OLLAMA_HOST'):env.pop(key,None)
        py=sys.executable
        builder=(a.build_python or (ROOT/'.venv-build/bin/python' if (ROOT/'.venv-build/bin/python').exists() else Path(py))).absolute()
        def check(key,category,command,severity='HIGH',timeout=180,artifact=None):
            if a.only and key not in a.only and not key.startswith('build_'):return
            if time.monotonic()>=deadline:raise TimeoutError('QA visit exceeded 30-minute execution limit')
            timeout=min(timeout,max(1,int(deadline-time.monotonic())))
            attempts=[];detail=''
            for trial in range(2):
                attempt=execute(command,work,env,out/'logs'/f'{key}-{trial+1}.log',timeout);attempts.append(attempt)
                if attempt['exit_code']==0:
                    if artifact:
                        try:
                            data=json.loads(artifact.read_text());assert data.get('passed') is True
                        except (OSError,ValueError,AssertionError):attempt['exit_code']=1;detail='Missing/invalid structured pass result'
                    if attempt['exit_code']==0:break
                # Output artifacts are exclusive; rerun to a new path rather than deleting evidence.
                if artifact:break
            success=attempts[-1]['exit_code']==0
            flaky=success and len(attempts)>1
            status='BLOCKED' if flaky else 'PASS' if success else 'FAIL'
            rows.append({'id':key,'category':category,'status':status,'severity':'NONE' if status=='PASS' else severity,
                         'detail':detail or ('Non-reproducible failure; investigate, do not silently pass' if flaky else 'Executed successfully' if success else 'See retained log'),
                         'attempts':attempts,'reproducible':len(attempts)==2 and not success,'command':list(map(str,command))})
            return status=='PASS'
        check('unit','unit',[py,'qa/unit.py','--suite','tests','--output',out/'unit.json'],artifact=out/'unit.json')
        check('qa_unit','unit',[py,'qa/unit.py','--suite','qa/tests','--output',out/'qa-unit.json'],artifact=out/'qa-unit.json')
        check('simulated_gui','simulated_gui',[py,'-m','unittest','discover','-s','tests','-p','test_*menu*.py','-v'])
        check('runner_fixtures','synthetic_forensics',[py,'validation_suite.py','--output',out/'synthetic.json'],artifact=out/'synthetic.json')
        check('malformed','synthetic_forensics',[py,'validation/macos_malformed_stress.py'])
        check('sqlite_lifecycle','synthetic_forensics',[py,'validation/macos_lifecycle.py'])
        portable=check('build_portable','build',[py,'build_cli.py'])
        native=False
        if (platform.system(),platform.machine())==('Darwin','arm64'):
            native=check('build_native','build',[builder,'build_native.py'],timeout=600)
        else:rows.append({'id':'build_native','category':'build','status':'BLOCKED','severity':'HIGH','detail':'Requires macOS ARM64 host'})
        if native and portable:
            packaged=check('build_release','build',[py,'build_release.py'])
            if packaged:
                archives=list((work/'dist/releases').glob('*.tar.gz'))
                if len(archives)!=1:raise ValueError('Expected exactly one newly built candidate')
                archive=archives[0];report['archive']={'path':str(archive),'sha256':digest(archive)}
                check('release_isolation','packaged',[py,'validation/clean_release_check.py',archive,out/'clean-release.json'],timeout=600,artifact=out/'clean-release.json')
                check('packaged_menus','interactive_pty',[py,'validation/packaged_menu_acceptance.py',archive,out/'packaged-menus.json'],timeout=600,artifact=out/'packaged-menus.json')
                # Test launchers from another extraction, never the build directory.
                extracted=out/'extracted'
                with tarfile.open(archive) as tar:tar.extractall(extracted,filter='data')
                release,=extracted.iterdir()
                for flavor,command in [('native',[release/'bin/llm-forensics']),('portable',[py,release/'llm-forensics.pyz'])]:
                    for key,script in [('failure_return','menu_failure_ack_check.py'),('large_roundtrip','review_report_roundtrip.py'),('capture_interrupt','interruption_check.py'),('bundle_interrupt','bundle_interruption_check.py')]:
                        check(flavor+'_'+key,'interactive_pty' if key=='failure_return' else 'packaged',[py,'validation/'+script,*command])
        if (out/'unit.json').exists() and (out/'packaged-menus.json').exists():
            check('menu_options','simulated_gui',[py,'qa/coverage.py',out],artifact=out/'menu-coverage.json')
        before=hashes;after=snapshot(source)[1]
        rows.append({'id':'input_preservation','category':'integrity','status':'PASS' if before==after else 'FAIL','severity':'NONE' if before==after else 'CRITICAL','detail':'Source snapshot unchanged' if before==after else 'Input source changed during QA; invalidate run'})
    except KeyboardInterrupt:
        rows.append({'id':'qa_interrupted','category':'infrastructure','status':'BLOCKED','severity':'HIGH','detail':'QA interrupted; partial results retained'})
    except Exception as exc:
        rows.append({'id':'qa_infrastructure','category':'infrastructure','status':'BLOCKED','severity':'HIGH','detail':type(exc).__name__+': '+str(exc)})
    for key,detail in MANDATORY_EXTERNAL.items():rows.append({'id':key,'category':key,'status':'NOT TESTED','severity':'HIGH','detail':detail})
    report['repair_history']=[json.loads(p.read_text()) for p in sorted((STATE/'repairs').glob('*.result.json')) if p.is_file()]
    report['fixes_applied']=[event['fix'] for event in report['repair_history'] if event.get('status')=='FIX_VERIFIED']
    automatic,ready,verdict=assess(rows,full=not a.only)
    report.update(automated_passed=automatic,deployment_ready=ready,production_ready=False,verdict=verdict,finished_utc=datetime.now(timezone.utc).isoformat(),partial=bool(a.only))
    write_json(out/'report.json',report);(out/'READINESS.md').write_text(render(report))
    print(json.dumps({'run':str(out),'report':str(out/'report.json'),'automated_passed':automatic,'deployment_ready':ready,'verdict':verdict}))
    return 0 if ready or (a.allow_missing_external and automatic) else 2 if automatic else 1
if __name__=='__main__':raise SystemExit(main())
