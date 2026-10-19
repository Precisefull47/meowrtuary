"""Exercise guided navigation and progress on an actual pseudo-terminal."""
import errno
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import tempfile
import time

command=sys.argv[1:]
if not command:raise SystemExit('Supply packaged CLI launcher')
with tempfile.TemporaryDirectory() as d:
    root=Path(d).resolve();master,slave=pty.openpty()
    process=subprocess.Popen(command,stdin=slave,stdout=slave,stderr=slave,start_new_session=True,env={**os.environ,'TERM':'xterm-256color','HOME':str(root)})
    os.close(slave);transcript=bytearray();buffer=bytearray()
    def until(marker):
        deadline=time.monotonic()+60
        while marker not in buffer:
            if time.monotonic()>deadline:raise RuntimeError('Timed out waiting for '+repr(marker))
            ready,_,_=select.select([master],[],[],.2)
            if ready:
                try:block=os.read(master,65536)
                except OSError as exc:
                    if exc.errno==errno.EIO:raise RuntimeError('Terminal ended early') from exc
                    raise
                if not block:raise RuntimeError('Terminal ended early')
                buffer.extend(block);transcript.extend(block)
        del buffer[:buffer.index(marker)+len(marker)]
    try:
        until(b'Q Quit');os.write(master,b'1\n')
        until(b'Standard settings');until(b'Select:');os.write(master,b'\n')
        until(b'Select:');os.write(master,b'2\n');until(b'Existing parent folder');os.write(master,str(root).encode()+b'\n')
        until(b'Start (y/n)');os.write(master,b'\n');until(b'Choose y or n')
        assert not list(root.glob('*/acquisition-manifest.json'))
        os.write(master,b'n\n');until(b'Q Quit')
        assert not list(root.glob('*/acquisition-manifest.json'))
        os.write(master,b'\x1b[B');until('› 2. Analyze'.encode());os.write(master,b'5\n');until(b'2. Synthetic validation');os.write(master,b'2\n')
        until(b'Select:');os.write(master,b'2\n');until(b'Existing parent folder');os.write(master,str(root).encode()+b'\n')
        until(b'Run synthetic validation');os.write(master,b'y\n')
        until(b'B Main menu')
        assert b'Running synthetic checks' in transcript
        assert json.loads(next(root.glob('validation-*/validation-results.json')).read_text())['passed']
        os.write(master,b'b');until(b'Q Quit');os.write(master,b'q')
        process.wait(timeout=10);assert process.returncode==0
        print(json.dumps({'passed':True,'launcher':Path(command[-1]).name,'checks':['explicit confirmation rejects Enter','cancelled scan creates no output','menu startup','guided destination','progress animation','synthetic job','compact result','return to menu','exit'],'terminal_bytes':len(transcript)}))
    finally:
        if process.poll() is None:process.kill();process.wait()
        os.close(master)
