"""Installed Ollama server in a new isolated HOME/model store; no conversation access."""
import json,os,socket,subprocess,sys,time,urllib.request
from pathlib import Path
root=Path(sys.argv[1]).resolve();root.mkdir(exist_ok=False)
home=root/'home';home.mkdir();models=root/'models';models.mkdir()
log=root/'input/.ollama/logs/server.log';log.parent.mkdir(parents=True)
with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
env={**os.environ,'HOME':str(home),'OLLAMA_HOST':f'127.0.0.1:{port}','OLLAMA_MODELS':str(models),'OLLAMA_NO_CLOUD':'1'}
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}));actions=[]
with log.open('wb') as stream:
 p=subprocess.Popen(['/Applications/Ollama.app/Contents/Resources/ollama','serve'],env=env,cwd=root,stdout=stream,stderr=stream)
 try:
  for _ in range(100):
   if p.poll() is not None:raise RuntimeError('Isolated server exited; inspect owned log')
   try:
    with opener.open(f'http://127.0.0.1:{port}/api/version',timeout=1) as response:version=json.load(response)
    break
   except OSError:time.sleep(.1)
  else:raise RuntimeError('Server startup timed out')
  for endpoint in ('/api/version','/api/tags'):
   with opener.open(f'http://127.0.0.1:{port}'+endpoint,timeout=3) as response:actions.append({'endpoint':endpoint,'status':response.status,'body':json.load(response)})
  assert actions[-1]['body']['models']==[]
 finally:
  p.terminate()
  try:p.wait(timeout=10)
  except subprocess.TimeoutExpired:p.kill();p.wait()
(root/'ground-truth.json').write_text(json.dumps({'passed':True,'version':version,'actions':actions,'scope':'Real installed Ollama server; isolated HOME/models, redirected log. No inference, prompts, personal conversations or model download.'},indent=2))
print('Controlled Ollama server capture passed')
