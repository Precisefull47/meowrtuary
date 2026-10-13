"""Optional macOS folder dialog and guarded menu output creation."""
import json
import os
from pathlib import Path
import subprocess
import sys

GUARD = 'LLMF_SELECTED_OUTPUT'


def browse_path(kind='folder', output=False):
    """Shared native file/folder selection; None means user cancellation."""
    if kind not in {'folder','file'}:raise ValueError('Unsupported picker type')
    if sys.platform != 'darwin':
        raise OSError('Native browsing requires macOS. Choose manual path entry.')
    prompt='Choose where to save the forensic output' if output else 'Choose an existing '+kind
    script = 'try\nset chosenItem to choose '+kind+' with prompt "'+prompt+'"\nreturn POSIX path of chosenItem\non error number -128\nreturn ""\nend try'
    try:
        result=subprocess.run(['/usr/bin/osascript','-e',script],capture_output=True,text=True,encoding='utf-8',timeout=300)
    except subprocess.TimeoutExpired as exc:
        raise OSError('Picker timed out. Browse again or enter a path manually.') from exc
    if result.returncode:raise OSError('Picker could not open. Choose manual path entry. '+result.stderr.strip())
    value=result.stdout.removesuffix('\n')
    if not value:return None
    path=Path(value)
    if not path.is_absolute() or '\x00' in value:raise OSError('Picker returned an invalid path. Enter a path manually.')
    return path


def browse_folder():
    return browse_path('folder',output=True)


def validate_parent(parent, sources=()):
    parent = Path(parent).expanduser().resolve(strict=True)
    if not parent.is_dir():raise ValueError('Select an existing parent folder.')
    if any((ancestor/'case-integrity.json').exists() or (ancestor/'acquisition-manifest.json').exists()
           for ancestor in (parent,*parent.parents)):
        raise ValueError('Choose a parent outside existing forensic cases to preserve their integrity.')
    for source in sources:
        boundary = Path(source).resolve()
        if parent == boundary or boundary in parent.parents:
            raise ValueError('Choose a storage folder outside the evidence source or input case.')
    if not os.access(parent, os.W_OK | os.X_OK):
        raise PermissionError('Selected folder is not writable. Choose another folder or check permissions.')
    return parent


def output_guard(output):
    parent = validate_parent(output.parent)
    info = parent.stat()
    return json.dumps({'output':str(output), 'parent':str(parent), 'device':info.st_dev, 'inode':info.st_ino})


def check_storage():
    value = os.environ.get(GUARD)
    if not value:return None
    guard = json.loads(value)
    info = Path(guard['parent']).stat()
    if (info.st_dev, info.st_ino) != (guard['device'], guard['inode']):
        raise OSError('Selected storage changed or disconnected. No alternate location will be used.')
    return guard


def create_output(output):
    output = Path(output)
    guard = check_storage()
    if guard and str(output) == guard['output']:
        # Do not recreate a missing selected parent (e.g. a disconnected volume).
        fd = os.open(guard['parent'], os.O_RDONLY | os.O_DIRECTORY)
        try:
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != (guard['device'], guard['inode']):
                raise OSError('Selected storage changed before output creation.')
            os.mkdir(output.name, mode=0o700, dir_fd=fd)
        finally:os.close(fd)
        check_storage()
    else:
        output.mkdir(parents=True, exist_ok=False, mode=0o700)
