"""Interrupt actual packaged acquisitions of owned synthetic files."""
import json,os,signal,subprocess,sys,tempfile,time,hashlib
from pathlib import Path

command=sys.argv[1:]
if not command:raise SystemExit('Supply launcher')
with tempfile.TemporaryDirectory(prefix='llmf-interrupt-') as temporary:
    root=Path(temporary).resolve();source=root/'evidence/.lmstudio/conversations';source.mkdir(parents=True)
    payload=b'{"messages":[{"role":"user","content":"CONTROLLED_INTERRUPT"}]}'
    for i in range(2000):(source/f'{i:04}.json').write_bytes(payload)
    case=root/'interrupted'
    p=subprocess.Popen(command+[str(root/'evidence'),'--acquire','--output',str(case)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    try:
        deadline=time.monotonic()+20
        while not (case/'acquisition-manifest.json').exists():
            if p.poll() is not None:raise AssertionError('Exited before acquisition')
            if time.monotonic()>deadline:raise AssertionError('Acquisition did not begin')
            time.sleep(.005)
        os.killpg(p.pid,signal.SIGINT)
        stdout,stderr=p.communicate(timeout=20)
        assert p.returncode==130,(p.returncode,stderr)
        m=json.loads((case/'acquisition-manifest.json').read_text())
        assert m['status']=='interrupted',m['status']
        assert not (case/'case-integrity.json').exists()
        assert not list(case.glob('*.pending'))
        assert all(f.read_bytes()==payload for f in source.iterdir())
        assert b'Traceback' not in stderr
        print(json.dumps({'passed':True,'exit_code':p.returncode,'manifest_status':m['status'],'source_files_unchanged':2000,'final_seal_absent':True,'scope':'Actual SIGINT to owned packaged acquisition; no personal data'}))
    finally:
        if p.poll() is None:p.kill();p.communicate()
