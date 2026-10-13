"""Compact keyboard-driven home screen with a plain-terminal fallback."""
from contextlib import contextmanager
import os
import select
import shutil
import sys
from . import __version__

# Display keys are local to each screen; action IDs preserve workflow routing.
HOME = [
    ('1','Scan this Mac','Discover supported local LLM artifacts on this Mac','1'),
    ('2','Analyze evidence','Capture evidence and generate a report','2'),
    ('3','Open a case','Browse saved case reports and exports','3'),
    ('4','Case tools','Verify, compare, export and package cases','cases'),
    ('5','Diagnostics & validation','Check this installation or run synthetic validation','diagnostics'),
]
CASE_TOOLS = [
    ('1','Verify case integrity','Check captured evidence and generated files for changes','4'),
    ('2','Compare two cases','Review differences between two saved cases','5'),
    ('3','Export reports','Copy reports from a saved case into a new folder','export'),
    ('4','Package a case','Create a verified portable case bundle','6'),
]
DIAGNOSTICS = [
    ('1','Runtime diagnostics','Check Python and required runtime components','doctor'),
    ('2','Synthetic validation','Run generated test evidence without scanning your profile','7'),
]

from .terminal import CAT_LOGO, DISPLAY_NAME, brand_lines
LOGO = CAT_LOGO


def startup_graphic():
    if not sys.stdout.isatty() or os.environ.get('TERM') == 'dumb':return
    print('\n'.join(brand_lines(shutil.get_terminal_size((80,24)).columns-1)))


def entries(page='home'):
    return {'home':HOME,'cases':CASE_TOOLS,'diagnostics':DIAGNOSTICS}[page]


def visible_items(more=False):
    page='cases' if more is True else more if isinstance(more,str) else 'home'
    return [row[:3] for row in entries(page)]


def screen(selected=0,more=False,width=80,height=24,version=False,error='',keyboard=True):
    import textwrap
    page='cases' if more is True else more if isinstance(more,str) else 'home'
    width=max(1,width-1)
    title={'home':DISPLAY_NAME,'cases':'Case tools','diagnostics':'Diagnostics & validation'}[page]
    heading='  '+DISPLAY_NAME+('  v'+__version__ if page=='home' else ' / '+title)
    lines=[heading,'']
    if page=='home' and keyboard and width>=32 and height>=22:
        lines=brand_lines(width)+['']
    items=entries(page)
    for i,(key,label,description,action) in enumerate(items):
        if width<32:label={'1':'Scan','2':'Analyze','3':'Reports','cases':'Case tools','diagnostics':'Diagnostics','4':'Verify','5':'Compare','export':'Export','6':'Package','doctor':'Diagnostics','7':'Validate'}[action]
        lines.append('  '+('› ' if i==selected else '  ')+f'{key}. {label}')
    lines+=['']
    description=items[selected][2] if selected is not None and 0<=selected<len(items) else 'Choose an option to continue.'
    lines+=['  '+line for line in textwrap.wrap(description,width=max(10,width-2))]
    shortcuts=(['↑ ↓ Navigate','Enter Select'] if keyboard else [])
    shortcuts+=['Q Quit'] if page=='home' else ['B Back','C Cancel']
    lines.append('')
    shortcut_line='  '
    for shortcut in shortcuts:
        addition=('   |   ' if shortcut_line.strip() else '')+shortcut
        if len(shortcut_line+addition)>width and shortcut_line.strip():
            lines.append(shortcut_line);shortcut_line='  '+shortcut
        else:shortcut_line+=addition
    lines.append(shortcut_line)
    if error:lines.append('  '+error)
    from .terminal import fit_line
    footer='  Q Quit' if page=='home' else '  B Back | C Cancel'
    if len(lines)>max(4,height-1):
        rows=[line for line in lines if any(f'{row[0]}. ' in line for row in items)]
        available=max(1,height-4)
        offset=max(0,min((selected or 0)-available+1,len(rows)-available))
        lines=[heading]+rows[offset:offset+available]+[footer]
    if not (sys.stdout.encoding or '').lower().replace('-','').startswith('utf8'):
        lines=[line.replace('›','>').replace('─','-').replace('·','|').replace('↑ ↓','Up/Down') for line in lines]
    text='\n'.join(fit_line(line,width).rstrip() for line in lines)+'\n'
    return text


@contextmanager
def keys():
    if os.name=='posix':
        import termios
        import tty
        fd=sys.stdin.fileno();old=termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd,termios.TCSANOW)
            yield fd
        finally:termios.tcsetattr(fd,termios.TCSANOW,old)
    else:yield None


def read_key(fd):
    if os.name=='nt':
        import msvcrt
        key=msvcrt.getwch()
        if key in ('\x00','\xe0'):return {'H':'up','P':'down'}.get(msvcrt.getwch(),'')
    else:
        raw=os.read(fd,1)
        if not raw:raise EOFError()
        if raw==b'\x1b':
            suffix=b''
            for _ in range(2):
                if select.select([fd],[],[],.1)[0]:suffix+=os.read(fd,1)
                else:break
            return {b'[A':'up',b'[B':'down',b'OA':'up',b'OB':'down'}.get(suffix,'')
        key=raw.decode('ascii',errors='ignore')
    if key in ('\r','\n'):return 'enter'
    if key in ('\x03','\x04'):return 'q'
    return key.lower()


def choose(animate=False):
    page='home';selected=0;error='';typed='';previous=None
    plain=os.environ.get('TERM')=='dumb'
    from .menu import styled,clear_screen
    from contextlib import nullcontext
    with (nullcontext(None) if plain else keys()) as fd:
        try:
            if not plain:clear_screen();print('\033[?25l',end='')
            while True:
                size=shutil.get_terminal_size((80,24))
                text=screen(None if plain else selected,more=page,width=size.columns,height=size.lines,error=error,keyboard=not plain)
                if plain or text!=previous:
                    if not plain:print('\033[H',end='')
                    from .terminal import motion_enabled
                    import time
                    reveal=False  # The startup vignette owns motion; menu appears immediately.
                    for index,line in enumerate(text.splitlines()):
                        rendered=styled(line,'1') if (line.startswith(('  › ','  > ')) or DISPLAY_NAME in line or any(line.strip().startswith(part.strip()) for part in LOGO)) else line
                        print(rendered+('\033[K' if not plain else ''))
                        if reveal and index<len(LOGO):
                            sys.stdout.flush();time.sleep(.035)
                    if not plain:print('\033[J',end='')
                    sys.stdout.flush()
                    previous=text
                if not plain and os.name=='posix' and not select.select([fd],[],[],.15)[0]:
                    continue
                key=input('  Select an option: ').strip().lower() if plain else read_key(fd)
                items=entries(page)
                if key=='q':return '0'
                if key in {'b','c'} and page!='home':
                    page='home';selected=0;typed='';error='';continue
                if not plain and key in {'up','down'}:
                    selected=((selected+(-1 if key=='up' else 1))%len(items)) if selected is not None else (len(items)-1 if key=='up' else 0)
                    typed='';error='';continue
                action=None
                if plain:
                    action=next((row[3] for row in items if row[0]==key),None)
                elif key=='enter' and selected is not None:
                    action=items[selected][3]
                elif key.isdigit():
                    typed+=key
                    selected=next((i for i,row in enumerate(items) if row[0]==typed),None)
                    error='' if selected is not None else 'Invalid option.'
                    continue
                if action in {'cases','diagnostics'}:
                    page=action;selected=0;typed='';error=''
                elif action:return action
                else:selected=None;typed='';error='Invalid option.'
        finally:
            if not plain:print('\033[?25h',end='',flush=True)
