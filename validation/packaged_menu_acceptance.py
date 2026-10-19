"""Run real PTY menu checks against a freshly relocated final release."""
import hashlib,json,subprocess,sys,tarfile,tempfile
from pathlib import Path
archive=Path(sys.argv[1]).resolve();output=Path(sys.argv[2]);base=Path(__file__).resolve().parent
results=[]
with tempfile.TemporaryDirectory(prefix='llmf-menu-relocated-') as directory:
    root=Path(directory)
    with tarfile.open(archive) as tar:tar.extractall(root,filter='data')
    release,=root.iterdir()
    for flavor,command in [('native',[str(release/'bin/llm-forensics')]),('portable',[sys.executable,str(release/'llm-forensics.pyz')])]:
        for script in ('folder_menu_workflows.py','ux_navigation_check.py','menu_pty_check.py','access_preflight_check.py'):
            result=subprocess.run([sys.executable,str(base/script)]+command,cwd=root,capture_output=True,text=True,timeout=120)
            row={'flavor':flavor,'script':script,'exit_code':result.returncode,'stdout':result.stdout,'stderr':result.stderr}
            row['passed']=result.returncode==0 and json.loads(result.stdout)['passed'];results.append(row)
    document={'archive':archive.name,'sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'passed':all(row['passed'] for row in results),'results':results,'limitations':'Real PTY; not native picker or GUI rendering certification.'}
    with output.open('x') as handle:json.dump(document,handle,indent=2)
    print(json.dumps({'passed':document['passed'],'groups':len(results),'output':str(output)}))
    if not document['passed']:raise SystemExit(1)
