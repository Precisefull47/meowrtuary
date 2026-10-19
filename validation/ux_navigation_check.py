"""Real PTY startup, resizing, Back/Cancel and noninteractive-banner checks."""
import fcntl,json,os,pty,select,struct,subprocess,sys,tempfile,termios,time
from pathlib import Path
command=sys.argv[1:];master,slave=pty.openpty();transcript=bytearray();buffer=bytearray()
def resize(columns):fcntl.ioctl(master,termios.TIOCSWINSZ,struct.pack('HHHH',24,columns,0,0))
resize(80)
p=subprocess.Popen(command,stdin=slave,stdout=slave,stderr=slave,env={**os.environ,'TERM':'xterm-256color'},start_new_session=True);os.close(slave)
def until(marker):
 deadline=time.monotonic()+30
 while marker not in buffer:
  if time.monotonic()>deadline:raise AssertionError((marker,bytes(transcript[-2500:])))
  if select.select([master],[],[],.1)[0]:
   data=os.read(master,65536)
   if not data:raise AssertionError('Terminal ended')
   buffer.extend(data);transcript.extend(data)
 index=buffer.index(marker)+len(marker);del buffer[:index]
def send(data):os.write(master,data)
try:
 until(b'Q Quit');assert b'( o.o )' in transcript and b'meowrtuary' in transcript
 send(b'12\n');until(b'Invalid option.');send(b'\x1b[B');until('› 1. Scan'.encode())
 resize(30);send(b'\x1b[B');until('› 2. Analyze'.encode())
 resize(100);send(b'\n');until(b'Evidence file or folder');until(b'Select:');send(b'3\n');until(b'Path:');send(b'b\n');until(b'Evidence file or folder');until(b'Select:');send(b'c');until(b'Q Quit')
 send(b'5\n');until(b'2. Synthetic validation');send(b'2\n');until(b'Save location:');until(b'Select:');send(b'c');until(b'Q Quit');send(b'q');p.wait(timeout=10)
 assert p.returncode==0
 assert b'( o.o )' in transcript and b'meowrtuary' in transcript
 assert transcript.count(b'\x1b[2J\x1b[H')>=6
 for flag in ('--help','--version','--doctor'):
  result=subprocess.run(command+[flag],capture_output=True,check=True)
  assert b'|_____||_____||_|' not in result.stdout
 print(json.dumps({'passed':True,'checks':['approved cat branding','arrow navigation and rapid invalid digits','30/80/100 column resize','manual Back to picker','Cancel to home','Validate Back to home','Quit','screen replacement on navigation','no graphic in help/version/doctor'],'scope':'Real PTY; no Terminal.app/iTerm2 or native-dialog visual certification'}))
finally:
 if p.poll() is None:p.kill();p.wait()
 os.close(master)
