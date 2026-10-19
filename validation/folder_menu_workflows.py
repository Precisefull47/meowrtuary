"""Packaged guided workflows with controlled evidence; no GUI interaction claimed."""
import errno,hashlib,json,os,pty,select,subprocess,sys,tempfile,time
from pathlib import Path
command=sys.argv[1:]
with tempfile.TemporaryDirectory(prefix='llmf-destination-') as d:
    root=Path(d).resolve();parent=root/('long-'+('x'*80))/'研究 reports';parent.mkdir(parents=True);source=root/'input/.ollama';source.mkdir(parents=True)
    evidence=source/'history';payload=b'KNOWN_FOLDER_DESTINATION_PROMPT\n';evidence.write_bytes(payload)
    master,slave=pty.openpty();env={**os.environ,'TERM':'dumb','HOME':str(root)}
    p=subprocess.Popen(command,cwd=root,stdin=slave,stdout=slave,stderr=slave,env=env,start_new_session=True);os.close(slave)
    transcript=bytearray();pending=bytearray()
    def until(marker):
        marker=marker.encode();deadline=time.monotonic()+60
        while marker not in pending:
            if time.monotonic()>deadline:raise AssertionError(('timeout',marker,bytes(transcript[-3000:])))
            if select.select([master],[],[],.1)[0]:
                try:raw=os.read(master,65536)
                except OSError as exc:raise AssertionError(('ended',bytes(transcript[-3000:]))) from exc
                if not raw:raise AssertionError('ended')
                pending.extend(raw);transcript.extend(raw)
        pos=pending.index(marker)+len(marker);del pending[:pos]
    def send(text):os.write(master,(text+'\n').encode())
    def choose(number):
        until('Select an option:')
        if number in {'4','5','6','7','export','doctor'}:
            send('5' if number in {'7','doctor'} else '4');until('Select an option:')
            number={'4':'1','5':'2','6':'4','7':'2','export':'3','doctor':'1'}[number]
        send(number)
    def destination():
        until('Select:');send('2');until('Existing parent folder');send(str(parent))

    try:
        choose('2');until('Evidence file or folder');until('Select:');send('3');until('Path:');send(str(root/'input'))
        until('Standard settings');until('Select:');send('');until('Source device name');send('QA Mac');destination()
        until('Start (y/n)');send('y');until('B Main menu')
        case,=parent.glob('QA-Mac_*');import re;assert re.fullmatch(r'QA-Mac_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}-\d{6}Z',case.name);assert b'Integrity verification: PASSED' in transcript
        report=json.loads((case/'report.json').read_text());assert len(report['findings'])==1
        assert (case/'conversations.json').exists() and (case/'timeline.csv').exists() and (case/'report.html').exists()
        assert evidence.read_bytes()==payload
        send('');choose('4');until('Case folder');until('Select:');send('2');until('Path:');send(str(case));until('Whole case: PASSED');until('Press Enter');send('')
        # Corrupt only a disposable copy; the original captured case stays sealed.
        import shutil
        damaged=root/'damaged';shutil.copytree(case,damaged)
        (damaged/'report.html').write_text('deliberate test corruption')
        choose('4');until('Case folder');until('Select:');send('2');until('Path:');send(str(damaged));until('Whole case: FAILED');until('Press Enter');send('')
        choose('5');until('Before case');until('Select:');send('3');until('Path:');send(str(case));until('After case');until('Select:');send('3');until('Path:');send(str(case));destination();until('Compare (y/n)');send('y');until('B Main menu')
        comparison,=parent.glob('comparison-*');assert json.loads((comparison/'comparison.json').read_text())['summary']=={'unchanged':1}
        send('');choose('6');until('Sealed case folder');until('Select:');send('2');until('Path:');send(str(case));destination();until('Create bundle');send('y');until('B Main menu')
        bundle,=parent.glob('bundle-*');assert hashlib.sha256((bundle/'case.tar.gz').read_bytes()).hexdigest()==(bundle/'case.tar.gz.sha256').read_text().split()[0]
        send('');choose('7');until('Select:');send('3');until('Run synthetic validation');send('y');until('B Main menu')
        kit,=root.glob('validation-*');assert json.loads((kit/'validation-results.json').read_text())['passed']
        send('');choose('3');until('Case folder');until('Select:');send('2');until('Path:');send(str(case))
        until('Available reports:');until('Select:');send('e');destination();until('Export report copies');send('y');until('B Reports')
        copies,=parent.glob('reports-*');assert (copies/'report.json').read_bytes()==(case/'report.json').read_bytes()
        assert json.loads((copies/'report-export.json').read_text())['source_integrity_verified']
        assert b'|_____||_____||_|' not in transcript  # TERM=dumb suppresses decoration
        import tarfile
        with tarfile.open(bundle/'case.tar.gz') as tar:tar.extractall(root/'unpacked',filter='data')
        verified=subprocess.run(command+['--verify-package',str(root/'unpacked/case')],capture_output=True,text=True,check=True)
        assert json.loads(verified.stdout)['verified']
        send('');until('Available reports:');until('Select:');send('c')
        choose('doctor');until('READY');until('Press Enter');send('')
        choose('export');until('Case folder');until('Select:');send('2');until('Path:');send(str(case));destination();until('Export report copies');send('y');until('B Main menu')
        assert len(list(parent.glob('reports-*')))==2
        send('')
        # Actual live Scan uses an isolated home containing only an owned history fixture.
        homehistory=root/'.ollama/history';homehistory.parent.mkdir();homehistory.write_bytes(payload)
        choose('1');until('Standard settings');until('Select:');send('');destination();until('Start (y/n)');send('y');until('B Main menu')
        cases=[p for p in parent.iterdir() if (p/'acquisition-manifest.json').is_file()];assert len(cases)==2
        live_case=next(p for p in cases if p!=case)
        from socket import gethostname
        assert live_case.name.startswith(gethostname().removesuffix('.local')+'_')
        live_report=json.loads((live_case/'report.json').read_text())
        assert any(r.get('text')==payload.decode().strip() for f in live_report['findings'] for r in f['observations'])
        assert homehistory.read_bytes()==payload
        send('');choose('q');p.wait(timeout=10);assert p.returncode==0
        # Restart a separate process and verify the saved case again.
        result=subprocess.run(command+['--verify-package',str(case)],cwd=root,capture_output=True,text=True,check=True)
        assert json.loads(result.stdout)['verified']
        print(json.dumps({'passed':True,'checks':['runtime diagnostics menu','direct report export menu','manual Unicode/space parent','Analyze acquisition and exports','actual saved integrity','Verify menu success and corrupted-case failure','Compare menu','Package menu and checksum','Validate suggested destination','restart and reverify','source bytes unchanged','Reports export copies','isolated HOME Scan (may read installed application Info.plist metadata)'],'count':13,'native_dialog_visually_verified':False}))
    finally:
        if p.poll() is None:p.kill();p.wait()
        os.close(master)
