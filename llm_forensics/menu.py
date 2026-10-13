"""Guided terminal interface. Existing argument-based commands remain unchanged."""
import itertools
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime
import uuid
import webbrowser
from . import __version__
from .terminal import motion_enabled, fit_line, DISPLAY_NAME
from .comparison import load_report
from .permission_help import has_access_denial, instructions, open_settings, probe_access
from .output_location import browse_folder, browse_path, validate_parent, output_guard, GUARD

_selected_outputs = {}
_step_label = ''


class Back(Exception):
    pass


class Cancel(Back):
    pass


def gather(steps):
    """Retain preceding answers; Back revisits one logical step, Cancel exits."""
    global _step_label
    state={};index=0
    while index<len(steps):
        name,prompt=steps[index]
        _step_label=f'Step {index+1} of {len(steps)}'
        try:
            header({'source':'Evidence', 'options':'Settings', 'output':'Save location', 'confirmed':'Review and confirm'}.get(name,name))
            state[name]=prompt(state);index+=1
        except Cancel:raise
        except Back:
            if index==0:raise
            index-=1
            for key,_ in steps[index:]:state.pop(key,None)
        finally:
            _step_label=''
    return state


def styled(text,code='36'):
    if sys.stdout.isatty() and os.environ.get('TERM')!='dumb' and 'NO_COLOR' not in os.environ:
        return f'\033[{code}m{text}\033[0m'
    return text


def safe(value):
    return ''.join(c if c.isprintable() else repr(c)[1:-1] for c in str(value))


def clear_screen():
    """Replace the visible screen without deleting terminal scrollback."""
    if sys.stdout.isatty() and os.environ.get('TERM')!='dumb':
        print('\033[2J\033[H',end='',flush=True)


def header(title='Workspace'):
    clear_screen()
    width=min(64,max(20,shutil.get_terminal_size((80,24)).columns-2))
    print(styled(fit_line('  '+DISPLAY_NAME+' / '+title+'  '+_step_label),'1'))
    print(styled('  '+'-'*(width-2),'2'))
    print()


def options(items, navigation=True):
    """One selectable item per line, shared by all guided submenus."""
    print()
    for key,label in items:print(f'  [{key}] {safe(label)}')
    if navigation:
        print('  [B] Back')
        print('  [C] Cancel')
    print()


def ask(label,default=None):
    suffix=f' [{default}]' if default is not None else ''
    value=input('  '+label+suffix+': ').strip()
    if value.lower() in {'c','cancel'}:raise Cancel()
    if value.lower() in {'b','back'}:raise Back()
    return value or (str(default) if default is not None else '')


def path_value(value):
    # Accept Terminal drag-and-drop escaped paths without evaluating shell syntax.
    try:
        parts=shlex.split(value)
        if len(parts)==1:value=parts[0]
    except ValueError:pass
    if not value.strip() or '\x00' in value:raise ValueError('Enter a nonempty path without NUL characters.')
    return Path(value).expanduser().absolute()


def source_path(label='Evidence file or folder',report=False,kind='either'):
    while True:
        header(label)
        print('  '+label)
        items=[('1','Browse folder')]
        if kind=='either':items.append(('2','Browse file'))
        manual='3' if kind=='either' else '2'
        items.append((manual,'Enter path'))
        options(items)
        try:
            choice=ask('Select')
            if choice=='1':path=browse_path('folder')
            elif choice=='2' and kind=='either':path=browse_path('file')
            elif choice==manual:
                try:
                    header(label)
                    path=path_value(ask('Path'))
                except Cancel:raise
                except Back:continue
            else:print('  Choose a displayed option.');continue
            if path is None:raise Cancel()
            if kind=='folder' and not path.is_dir():raise ValueError('Select an existing folder.')
            if not path.exists():raise ValueError('Path unavailable. Choose another path.')
            if report and path.is_dir():path=path/'report.html'
            if report and (not path.is_file() or path.suffix.lower()!='.html'):raise ValueError('Select an HTML report.')
            return path
        except (OSError,ValueError) as exc:print('  '+safe(exc))


def destination(prefix, sources=()):
    suggested=Path.home()
    while True:
        print('  Save location:')
        options([('1','Browse folder'),('2','Enter path'),('3','Suggested: '+str(suggested))])
        choice=ask('Select')
        try:
            if choice=='1':
                parent=browse_folder()
                if parent is None:
                    print('  Folder selection cancelled. No operation started.')
                    raise Cancel()
            elif choice=='2':
                try:
                    header('Save location')
                    parent=path_value(ask('Existing parent folder'))
                except Cancel:raise
                except Back:continue
            elif choice=='3':parent=suggested
            else:
                print('  Choose 1, 2, 3 or b.');continue
            parent=validate_parent(parent,sources)
            output=parent/(prefix+'-'+datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+uuid.uuid4().hex[:8])
            if output.exists() or output.is_symlink():
                print('  Output name conflicts with an existing entry. Choose again.');continue
            print('\n  Selected location: '+safe(parent))
            print('  A new output directory will be created: '+safe(output.name))
            parent=validate_parent(parent,sources)
            _selected_outputs[str(output)]=output_guard(output)
            return output
        except (OSError,ValueError) as exc:
            print('  '+safe(exc))
            print('  Choose Browse again, manual path entry, or Back. No output created.')


def yes(label):
    print('  '+label)
    options([('Y','Confirm'),('N','Do not proceed')])
    while True:
        answer=ask(label+' (y/n)').lower()
        if answer in {'y','yes'}:return True
        if answer in {'n','no'}:return False
        print('  Choose y or n; B goes back, C cancels.')


def launcher():
    if getattr(sys,'frozen',False):return [sys.executable]
    if sys.argv[0].endswith('.pyz'):return [sys.executable,str(Path(sys.argv[0]).absolute())]
    return [sys.executable,'-m','llm_forensics']


def stop_child(process):
    if process.poll() is not None:return
    if os.name=='posix':os.killpg(process.pid,signal.SIGINT)
    else:process.terminate()
    try:process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        if os.name=='posix':os.killpg(process.pid,signal.SIGKILL)
        else:process.kill()
        process.wait()


def run_job(arguments,label):
    """Real elapsed time with an indeterminate spinner; no invented percentages."""
    header(label)
    animated=motion_enabled()
    start=time.monotonic();frames=itertools.cycle('|/-\\');process=None
    with tempfile.TemporaryFile(mode='w+b') as log:
        try:
            env=dict(os.environ)
            env.pop(GUARD,None)
            if '--output' in arguments:
                selected=str(arguments[arguments.index('--output')+1])
                if selected in _selected_outputs:env[GUARD]=_selected_outputs.pop(selected)
            process=subprocess.Popen(launcher()+list(map(str,arguments)),env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=os.name=='posix')
            if animated:print('\033[?25l',end='',flush=True)
            else:print('  '+label+'...',flush=True)
            while process.poll() is None:
                if animated:
                    width=max(1,shutil.get_terminal_size((80,24)).columns-1)
                    line=f'  {next(frames)} {label}  {int(time.monotonic()-start)}s'
                    print('\r\033[2K'+styled(fit_line(line,width),'1'),end='',flush=True)
                time.sleep(.1)
            code=process.returncode
        except KeyboardInterrupt:
            if process is not None:stop_child(process)
            print('\n  Cancelled. Retain any partial case; inspect its manifest before use.')
            raise Back()
        finally:
            if animated:print('\r\033[2K\033[?25h',end='',flush=True)
        log.seek(0,2);length=log.tell();log.seek(max(0,length-6000))
        tail=log.read().decode('utf-8',errors='replace')
        if code and str(arguments[0]) in {'--verify-case','--verify-package'} and length<=16*1024*1024:
            log.seek(0)
            try:
                result=json.loads(log.read())
                failures=[v for v in result.get('files',[]) if v.get('status')!='verified']
                if failures:tail='\n'.join(str(v.get('status'))+': '+str(v.get('path',v.get('case_path','unknown file'))) for v in failures[:5])
            except (ValueError,TypeError):pass
    if code not in (0,3):
        print(styled('  Failed: operation did not complete.','1'))
        lines=[safe(line) for line in tail.splitlines() if line.strip()]
        for line in lines[-5:]:print('  '+line)
        return False,tail
    if code==3:print('  Completed with gaps; inspect the report before relying on the results.')
    print(styled(f'  Completed in {time.monotonic()-start:.1f}s','32'))
    return True,tail


def open_report(path):
    if not webbrowser.open(path.resolve().as_uri()):print('  Open this file in your browser: '+safe(path))


def result_actions(output,return_label='Main menu'):
    report=output/'report.json';html=output/'report.html'
    if not html.exists():html=output/'comparison.html'
    data=None
    if report.exists():
        try:
            data,_=load_report(report)
            coverage=data.get('coverage_summary',{})
            print('\n  '+styled(coverage.get('status','unknown').replace('_',' ').upper(),'1'))
            print(f"  {len(data['findings'])} artifacts  |  {len(coverage.get('gaps',[]))} coverage gaps")
            if coverage.get('status')!='complete_within_scope':print('  Some checks were incomplete. Review the report for details.')
        except (OSError,ValueError):print('  Summary unavailable; inspect the output files.')
    denied=bool(data and has_access_denial(data))
    if denied:print('  macOS blocked selected locations. Press P for access guidance and settings.')
    print('\n  Saved to '+safe(output))
    if (output/'case.tar.gz.sha256').is_file():
        print('  Bundle checksum: '+safe((output/'case.tar.gz.sha256').read_text()[:64]))
    if (output/'validation-results.json').is_file():
        try:
            result=json.loads((output/'validation-results.json').read_text())
            print('  Synthetic validation: '+('PASSED' if result.get('passed') is True else 'FAILED')+' (generated fixtures only)')
        except (OSError,ValueError):print('  Validation summary unavailable; inspect saved results.')
    while True:
        items=[('B',return_label)]
        if denied:items.append(('P','Access settings'))
        if sys.platform=='darwin':items.append(('F','Open output folder'))
        if html.exists():items.append(('O','Open report'))
        if data:items.append(('D','Details'))
        options(items,navigation=False)
        action=input('  > ').strip().lower()
        if action in {'','b','back','c','cancel'}:return
        if action=='p' and denied:
            print('\n'+instructions())
            try:
                if yes('Open System Settings'):open_settings()
            except Back:continue
            except OSError as exc:print('  '+safe(exc))
        elif action=='f' and sys.platform=='darwin':
            try:
                opened=subprocess.run(['/usr/bin/open',str(output)],capture_output=True,text=True,timeout=15)
                if opened.returncode:print('  Finder could not open this folder: '+safe(opened.stderr))
            except (OSError,subprocess.TimeoutExpired) as exc:print('  Finder could not open this folder: '+safe(exc))
        elif action=='o' and html.exists():open_report(html)
        elif action=='d' and data:
            from .terminal import artifact_table
            print('\n'+artifact_table(data['findings']))
        else:print('  Choose one of the displayed options.')


def scan_options(live):
    while True:
        system='macos';args=[]
        options([('1','Standard settings (default)'),('2','Advanced settings')])
        setting=ask('Select').lower()
        if setting in {'','1'}:return ['--include-trash'] if live and sys.platform=='darwin' else args if live else ['--source-os',system]
        if setting not in {'a','2'}:print('  Choose 1, 2, B or C.');continue
        try:
            header('Advanced settings')
            if not live:
                options([('1','macOS'),('2','Windows'),('3','Linux'),('4','Unknown')])
                while True:
                    system=ask('Evidence OS','1').lower()
                    system={'1':'macos','2':'windows','3':'linux','4':'unknown'}.get(system,system)
                    if system in {'macos','windows','linux','unknown'}:break
                    print('  Choose a listed OS.')
            header('Historical residue')
            if yes('Check historical residue'):args+=['--recover-deleted']
            if live and sys.platform=='darwin':
                header('Trash coverage')
                if yes('Include readable Trash'):args+=['--include-trash']
            return args if live else args+['--source-os',system]
        except Cancel:raise
        except Back:continue


def access_preflight(paths):
    while True:
        rows=probe_access(paths)
        blocked=[row for row in rows if row['status'] not in {'readable','not_found'}]
        if not blocked:
            print('  Access precheck: existing selected roots are readable.')
            print('  This is not a full-scan guarantee; deeper gaps may appear during capture.')
            return
        print('  Access precheck: selected scope has access gaps.')
        for row in blocked[:5]:print('  '+safe(row['path'])+' - '+row['status'])
        denied=any(row['status']=='denied' for row in blocked)
        if denied:
            print('  Full Disk Access may help. Enable your launching app, then restart it.')
        items=[('S','Full Disk Access settings')] if denied else []
        options(items+[('R','Recheck'),('L','Continue with gaps')])
        answer=ask('Select').lower()
        if answer=='s' and denied:
            print(instructions())
            try:open_settings()
            except OSError as exc:print('  '+safe(exc))
        elif answer=='r':continue
        elif answer=='l':return
        else:print('  Choose a displayed option. No scan has started.')


def scan_flow(live):
    header('Scan' if live else 'Analyze')
    print('  Create a new evidence case.')
    def evidence(state):
        source=source_path()
        if source.is_dir() and (source/'acquisition-manifest.json').is_file() and (source/'evidence').is_dir():
            source=source/'evidence'
            print('  Using captured evidence; quarantined files stay excluded.')
        return source
    def output(state):
        if live:
            from .live import discover
            _,boundaries,_=discover(include_trash='--include-trash' in state['options'])
        else:boundaries=[state['source']]
        return destination('case',sources=boundaries)
    def review(state):
        if live:
            from .live import discover
            _,paths,_=discover(include_trash='--include-trash' in state['options'])
            print('  Scope: known LLM locations'+(' + readable Trash' if '--include-trash' in state['options'] else ' (Trash excluded)'))
            access_preflight(paths)
        print('  Source: '+('This Mac - known LLM locations' if live else safe(state['source'])))
        print('  Historical residue: '+('Enabled' if '--recover-deleted' in state['options'] else 'Disabled'))
        print('  Capture, conversations, timeline and reports')
        print('  Output: '+safe(state['output']))
        return yes('Start')
    steps=[] if live else [('source',evidence)]
    state=gather(steps+[('options',lambda _:scan_options(live)),('output',output),('confirmed',review)])
    if not state['confirmed']:return
    args=(['--live'] if live else [str(state['source'])])+state['options']
    output=state['output']
    ok,_=run_job(args+['--acquire','--timeline','--format','both','--export-conversations','--output',output],'Scanning and preparing reports')
    if ok:
        verified,_=run_job(['--verify-package',output],'Verifying saved case')
        print('  Integrity verification: '+('PASSED (unsigned manifest)' if verified else 'FAILED; retain and inspect this case'))
        result_actions(output)
    else:input('\n  Press Enter to return...')


def output_flow(prefix, inputs, operation, label, confirmation):
    steps=[(name,lambda state,label=title,kind=kind:source_path(label,kind=kind)) for name,title,kind in inputs]
    def review(state):
        for name,title,_ in inputs:print('  '+title+': '+safe(state[name]))
        print('  Output: '+safe(state['output']))
        return yes(confirmation)
    steps += [('output',lambda state:destination(prefix,sources=[state[name] for name,_,_ in inputs])),
              ('confirmed',review)]
    state=gather(steps)
    if not state['confirmed']:return
    args=[operation]+[state[name] for name,_,_ in inputs]+['--output',state['output']]
    ok,_=run_job(args,label)
    if ok:result_actions(state['output'])
    else:input('\n  Press Enter to return...')


def reports_flow():
    from .report_export import available_reports
    header('Reports')
    while True:
        case=source_path('Case folder',kind='folder')
        while True:
            reports=available_reports(case)
            if not reports:
                print('  No supported reports found. Select another case or B to return.');break
            header('Available reports')
            print('\n  Available reports:')
            for number,path in enumerate(reports,1):print(f'  [{number}] Open {safe(path.name)}')
            options([('E','Export copies'),('B','Back to case selection'),('C','Cancel to main menu')],navigation=False)
            try:action=ask('Select').lower()
            except Cancel:raise
            except Back:break
            try:
                if action=='e':
                    state=gather([('output',lambda _:destination('reports',sources=[case])),
                                  ('confirmed',lambda _:yes('Export report copies'))])
                    if not state['confirmed']:continue
                    ok,_=run_job(['--export-reports',case,'--output',state['output']],'Exporting and verifying report copies')
                    if ok:result_actions(state['output'],return_label='Reports')
                elif action.isdigit() and 1<=int(action)<=len(reports):open_report(reports[int(action)-1])
                else:print('  Choose a report number, E, B or C.')
            except Cancel:raise
            except Back:continue
            except (OSError,ValueError) as exc:print('  '+safe(exc))


def menu():
    """Keep the guided UI out of shell scrollback; restore on every exit path."""
    interactive=(sys.stdin.isatty() and sys.stdout.isatty()
                 and os.environ.get('TERM') not in (None, '', 'dumb'))
    try:
        if interactive:
            print('\033[?1049h\033[H',end='',flush=True)
            from .startup import play
            play()
        return _menu()
    finally:
        if interactive:
            print('\033[0m\033[?25h\033[?1049l',end='',flush=True)


def _menu():
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print('The guided menu needs an interactive terminal. Use --help for scriptable commands.')
        return
    first_screen=True
    while True:
        try:
            from .menu_navigation import choose
            choice=choose(animate=first_screen)
            first_screen=False
            if choice=='0':print('\n  Goodbye.\n');return
            if choice in {'1','2'}:scan_flow(choice=='1')
            elif choice=='3':reports_flow()
            elif choice=='export':
                header('Export reports')
                output_flow('reports',[('case','Case folder','folder')],
                            '--export-reports','Exporting and verifying report copies','Export report copies')
            elif choice=='doctor':
                header('Runtime diagnostics')
                from .diagnostics import diagnose
                result=diagnose()
                print('  '+styled('READY' if result['passed'] else 'CHECKS FAILED','32' if result['passed'] else '33'))
                for check in result['checks']:
                    print('  '+('PASS' if check['passed'] else 'FAIL')+'  '+check['name']+'  '+safe(check.get('detail') or check.get('version') or ''))
                print('\n  '+result['scope'])
                input('\n  Press Enter to return...')
            elif choice=='4':
                header('Verify');case=source_path('Case folder',kind='folder')
                modes=[]
                if (case/'acquisition-manifest.json').exists():modes.append(('--verify-case','Raw evidence'))
                if (case/'case-integrity.json').exists():modes.append(('--verify-package','Whole case'))
                if not modes:print('  No supported integrity manifest found in this folder.')
                for mode,label in modes:
                    ok,_=run_job([mode,case],label+' verification')
                    print('  '+label+': '+('PASSED against unsigned manifest' if ok else 'FAILED'))
                input('\n  Press Enter to return...')
            elif choice=='5':
                header('Compare')
                output_flow('comparison',[('before','Before case','either'),('after','After case','either')],
                            '--compare','Comparing cases','Compare')
            elif choice=='6':
                header('Package')
                print('  Bundles contain sensitive evidence; they are not encrypted.')
                output_flow('bundle',[('case','Sealed case folder','folder')],
                            '--bundle-case','Verifying and packaging case','Create bundle (contains sensitive evidence; not encrypted)')
            elif choice=='7':
                header('Validate')
                print('  Synthetic checks only; no personal evidence is scanned.')
                output_flow('validation',[],'--self-test','Running synthetic checks','Run synthetic validation')
            else:print('  Choose a number from 0 to 7.');input('  Press Enter to continue...')
        except Cancel:
            print('  Operation cancelled.');continue
        except Back:continue
        except EOFError:print('\n  Goodbye.');return
        except KeyboardInterrupt:
            print('\n  Operation cancelled.');continue
        except (OSError,ValueError) as exc:
            print('  Unable to continue: '+safe(exc))
            try:input('  Press Enter to return...')
            except (EOFError,KeyboardInterrupt):return
