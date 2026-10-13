"""Small, optional ASCII cat vignette. Never reads or consumes keyboard input."""
import shutil
import sys
import time
from .terminal import motion_enabled


def frame(step):
    canvas=[list(' '*40) for _ in range(11)]
    def put(x,y,text):
        canvas[y][x:x+len(text)]=text
    put(23,0,'   .-~~~~-.')
    put(23,1,' .(  o  o  ).')
    put(23,2,'(  o     o  )')
    put(23,3," `---.__.---'")
    put(28,4,'||')
    put(28,5,'||')
    put(25,6,'___||___')
    x=(3,9,15,20,20,20,14,8)[step]
    raised=step in (3,4)
    y=3 if raised else 4
    put(x,y,' /\\_/\\')
    put(x,y+1,'( o.o )'+('/' if raised else ''))
    put(x,y+2,' /|_|\\')
    put(x,y+3,'  / \\')
    if step<4:put(24,4,'o')
    elif step==4:put(26,3,'o')
    else:put(x+7,y+1,'o')
    put(2,9,'meowrtuary')
    put(2,10,'A little curiosity. A lot of evidence.')
    return '\n'.join(''.join(row).rstrip() for row in canvas)


def play():
    if not motion_enabled():return
    size=shutil.get_terminal_size((80,24))
    if size.columns<42 or size.lines<14:return
    try:
        sys.stdout.write('\033[?25l')
        for step in range(8):
            size=shutil.get_terminal_size((80,24))
            if size.columns<42 or size.lines<14:break
            sys.stdout.write('\033[H'+'\n'.join(line+'\033[K' for line in frame(step).splitlines())+'\033[J')
            sys.stdout.flush()
            time.sleep(.3125)
    finally:
        sys.stdout.write('\033[H\033[J\033[?25h')
        sys.stdout.flush()
