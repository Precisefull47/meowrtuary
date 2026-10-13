"""Evidence-free deployment checks, available before parser imports."""
import importlib
import platform
import sys
from . import __version__


def diagnose():
    checks=[{'name':'python','passed':sys.version_info >= (3,10),'version':platform.python_version()}]
    for name in ('sqlite3','zlib'):
        try:
            module=importlib.import_module(name)
            if name=='sqlite3':
                connection=module.connect(':memory:')
                try:assert connection.execute('SELECT 1').fetchone()==(1,)
                finally:connection.close()
            else:assert module.decompress(module.compress(b'check'))==b'check'
            checks.append({'name':name,'passed':True,'version':getattr(module,'sqlite_version',getattr(module,'ZLIB_VERSION',None))})
        except (ImportError,OSError,RuntimeError,AssertionError) as exc:
            checks.append({'name':name,'passed':False,'detail':str(exc)})
    return {'tool_version':__version__,'passed':all(c['passed'] for c in checks),'platform':platform.system(),'architecture':platform.machine(),'frozen':bool(getattr(sys,'frozen',False)),'checks':checks,'scope':'Runtime checks only; no evidence read, no disk case created, no runner execution, no permission certification.'}
