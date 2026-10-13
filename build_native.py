"""Build on the target OS; never claim to cross-compile a native executable."""
import os
from pathlib import Path
import platform
import subprocess
import sys

root = Path(__file__).resolve().parent
target = f"{platform.system().lower()}-{platform.machine().lower()}"
env = dict(os.environ, PYINSTALLER_CONFIG_DIR=str(root / "build" / "pyinstaller-cache"))
subprocess.run([
    sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir",
    "--name", "llm-forensics", "--distpath", str(root / "dist" / target),
    "--workpath", str(root / "build" / target), "--specpath", str(root / "build"),
    str(root / "cli_entry.py"),
], cwd=root, env=env, check=True)
print(f"Native bundle: {root / 'dist' / target / 'llm-forensics'}")
