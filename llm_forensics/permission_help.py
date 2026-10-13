"""Actionable macOS access guidance; never grant or certify permissions."""
import os
import stat
from pathlib import Path
import subprocess
import sys


def has_access_denial(report):
    if sys.platform != 'darwin':return False
    gaps=report.get('coverage_summary',{}).get('gaps',[])
    for gap in gaps:
        detail=str(gap.get('detail','')).lower()
        if gap.get('status') in {'permission_denied','access_denied'} or any(
            marker in detail for marker in ('[errno 1]', '[errno 13]', 'operation not permitted', 'permission denied')):
            return True
    return False


def instructions():
    return ('macOS denied access to one or more selected locations.\n'
            'Full Disk Access may help; ordinary file permissions or managed restrictions can also block access.\n'
            'Open System Settings > Privacy & Security > Full Disk Access.\n'
            'If authorized, enable the app that launches this tool (Terminal for the .command launcher;\n'
            'otherwise your terminal or host app). This grants that app broad access to private files.\n'
            'Quit and reopen that app, then run a NEW scan into a NEW case. Keep this partial case unchanged.\n'
            'The tool cannot grant access or confirm that a toggle change succeeded.\n'
            'Full Disk Access does not guarantee a full-disk scan or recovery; review the new coverage gaps.')


def open_settings():
    """Open settings only on an explicit menu action; do not change any setting."""
    try:
        result=subprocess.run(['/usr/bin/open','x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles'],capture_output=True,text=True,timeout=15)
        if result.returncode:raise OSError('Could not open System Settings. Open it from the Apple menu.')
    except subprocess.TimeoutExpired as exc:
        raise OSError('Opening System Settings timed out. Open it from the Apple menu.') from exc


def probe_access(paths):
    """Read-only top-level access probes, not a TCC toggle or recursive coverage test."""
    rows=[]
    for path in dict.fromkeys(map(Path,paths)):
        row={'path':str(path),'status':'readable'}
        try:
            mode=path.lstat().st_mode
            if stat.S_ISDIR(mode):
                with os.scandir(path) as entries:next(entries,None)
            elif stat.S_ISREG(mode):
                fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
                os.close(fd)
            else:row['status']='unsupported_path'
        except FileNotFoundError:row['status']='not_found'
        except PermissionError as exc:row.update(status='denied',detail=str(exc))
        except OSError as exc:row.update(status='unavailable',detail=str(exc))
        rows.append(row)
    return rows
