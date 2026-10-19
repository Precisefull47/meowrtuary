"""Interrupt packaging of owned random data; preserve source and incomplete output."""
import hashlib,json,os,signal,subprocess,sys,tempfile,time
from pathlib import Path
command=sys.argv[1:]
with tempfile.TemporaryDirectory(prefix='llmf-bundle-interrupt-') as d:
 root=Path(d).resolve();case=root/'case';case.mkdir();(case/'report.json').write_text('{}')
 data=os.urandom(32*1024*1024);(case/'controlled.bin').write_bytes(data)
 subprocess.run(command+['--seal-case',str(case)],check=True,capture_output=True)
 hashes={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in case.iterdir()}
 out=root/'bundle';p=subprocess.Popen(command+['--bundle-case',str(case),'--output',str(out)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
 try:
  deadline=time.monotonic()+20
  while not (out/'case.tar.gz.partial').exists():
   if p.poll() is not None:raise AssertionError('Bundle finished before interrupt')
   if time.monotonic()>deadline:raise AssertionError('No partial bundle')
   time.sleep(.002)
  os.killpg(p.pid,signal.SIGINT);stdout,stderr=p.communicate(timeout=20)
  assert p.returncode==130 and not (out/'case.tar.gz').exists() and not (out/'case.tar.gz.sha256').exists()
  assert hashes=={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in case.iterdir()}
  assert b'Traceback' not in stderr
  subprocess.run(command+['--verify-package',str(case)],check=True,capture_output=True)
  print(json.dumps({'passed':True,'exit_code':130,'source_unchanged':True,'no_completed_bundle':True,'scope':'Actual SIGINT to owned packaging process'}))
 finally:
  if p.poll() is None:p.kill();p.communicate()
