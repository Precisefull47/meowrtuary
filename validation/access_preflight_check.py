"""Packaged PTY: denied synthetic Trash blocks capture until explicit choice."""
import json, os, pty, select, subprocess, sys, tempfile, time
from pathlib import Path
with tempfile.TemporaryDirectory(prefix='llmf-access-') as folder:
    root=Path(folder); trash=root/'.Trash'; trash.mkdir(); trash.chmod(0)
    out=root/'outputs';out.mkdir()
    master,slave=pty.openpty()
    p=subprocess.Popen(sys.argv[1:],stdin=slave,stdout=slave,stderr=slave,cwd=root,env={**os.environ,'HOME':str(root),'TERM':'dumb'},start_new_session=True)
    os.close(slave); pending=bytearray(); transcript=bytearray()
    def until(marker):
        marker=marker.encode(); deadline=time.monotonic()+30
        while marker not in pending:
            if time.monotonic()>deadline:raise AssertionError(bytes(transcript[-2500:]))
            if select.select([master],[],[],.1)[0]:
                data=os.read(master,65536);pending.extend(data);transcript.extend(data)
        del pending[:pending.index(marker)+len(marker)]
    def send(value):os.write(master,(value+'\n').encode())
    def start():
        until('Select an option:');send('1');until('Standard settings');until('Select:');send('');until('Select:');send('2');until('Existing parent folder');send(str(out))
    try:
        start();until('Continue with gaps');until('Select:');send('');until('No scan has started.');assert not list(out.iterdir())
        until('Select:');send('c');until('Select an option:');send('1');until('Standard settings');until('Select:');send('');until('Select:');send('2');until('Existing parent folder');send(str(out))
        until('Continue with gaps');until('Select:');trash.chmod(0o700);send('r');until('existing selected roots are readable.');until('Start (y/n)');send('n')
        until('Select an option:');send('q');p.wait(timeout=10);assert p.returncode==0;assert not list(out.iterdir())
        print(json.dumps({'passed':True,'checks':['denied Trash detected before capture','blank does not consent','cancel creates no case','recheck detects restored access','start still requires confirmation']}))
    finally:
        trash.chmod(0o700)
        if p.poll() is None:p.kill();p.wait()
        os.close(master)
