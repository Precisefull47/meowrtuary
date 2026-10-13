"""Build a portable Python zip application without embedding evidence files."""
from pathlib import Path
import shutil
import tempfile
import zipapp

root = Path(__file__).resolve().parent
output = root / "dist" / "llm-forensics.pyz"
output.parent.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory() as temp:
    stage = Path(temp)
    destination=stage / "llm_forensics"
    destination.mkdir()
    for source in (root / "llm_forensics").glob('*.py'):
        if source.is_symlink():raise ValueError('Source module links are not distributable')
        shutil.copy2(source,destination/source.name)
    zipapp.create_archive(stage, target=output, main="llm_forensics.__main__:entry_point", interpreter="/usr/bin/env python3")
print(output)
