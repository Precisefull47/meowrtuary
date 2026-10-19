"""Actual menu failure and return: selected storage replacement and explicit output collision."""
import json,os,pty,re,select,subprocess,sys,tempfile,time
from pathlib import Path
with tempfile.TemporaryDirectory(prefix='llmf-menu-failure-') as folder:
    root=Path(folder);source=root/'source/.ollama';source.mkdir(parents=True);(source/'history').write_text('CONTROLLED_FAILURE_ACK\n')
    output=root/'output';output.mkdir();master,slave=pty.openpty()
    p=subprocess.Popen(sys.argv[1:],stdin=slave,stdout=slave,stderr=slave,cwd=root,env={**os.environ,'TERM':'dumb'},start_new_session=True);os.close(slave)
    pending=bytearray();transcript=bytearray()
    def until(marker):
        marker=marker.encode();deadline=time.monotonic()+30
        while marker not in pending:
            if time.monotonic()>deadline:raise AssertionError(bytes(transcript[-3000:]))
            if select.select([master],[],[],.1)[0]:
                block=os.read(master,65536);pending.extend(block);transcript.extend(block)
        del pending[:pending.index(marker)+len(marker)]
    def send(value):os.write(master,(value+'\n').encode())
    try:
        until('Select an option:');send('2');until('Select:');send('3');until('Path:');send(str(source.parent))
        until('Standard settings');until('Select:');send('1');until('Source device name');send('QA Mac');until('Select:');send('2');until('Existing parent folder');send(str(output));until('Start (y/n)')
        held=root/'held-output';output.rename(held);output.mkdir()
        collision=output/'sentinel-case';collision.mkdir();(collision/'sentinel').write_text('keep')
        send('y');until('Failed: operation did not complete.');until('Press Enter to return');send('');until('Select an option:');send('q');p.wait(timeout=10)
        assert p.returncode==0;assert list(collision.iterdir())==[collision/'sentinel'];assert (collision/'sentinel').read_text()=='keep'
        retry=subprocess.run(sys.argv[1:]+[str(source.parent),'--acquire','--output',str(collision)],capture_output=True,text=True)
        assert retry.returncode!=0 and (collision/'sentinel').read_text()=='keep'
        assert sorted(p.name for p in output.iterdir())==['sentinel-case']
        assert (source/'history').read_text()=='CONTROLLED_FAILURE_ACK\n'
        print(json.dumps({'passed':True,'checks':['replaced storage refused','explicit collision refused without overwrite','failure acknowledgement returns to main','clean Quit after failed job','source preserved']}))
    finally:
        if p.poll() is None:p.kill();p.wait()
        os.close(master)
