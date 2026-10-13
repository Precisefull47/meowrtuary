# Third-party notices

The MIT license in LICENSE covers original meowrtuary code, not its dependencies.
The native runtime includes these separately licensed components:

- CPython: Python license and included notices (licenses/Python.txt).
- PyInstaller bootloader: GPL with distribution exception (licenses/PyInstaller.txt).
- OpenSSL: Apache License 2.0 (licenses/OpenSSL.txt).
- liblzma: BSD Zero Clause (licenses/liblzma.txt).
- mpdecimal: upstream COPYRIGHT notice (licenses/mpdecimal.txt).
- Zstandard: BSD license option (licenses/zstd.txt).
- SQLite: public domain (licenses/SQLite.txt).

System libraries supplied by macOS are not redistributed as part of this archive.
These notices correspond to the currently packaged runtime. Re-audit bundled
libraries and retain appropriate notices when changing build dependencies.
