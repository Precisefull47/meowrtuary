# meowrtuary

A macOS command-line tool for examining local LLM artifacts from Ollama,
LM Studio and llama.cpp. Research preview; internal version 1.4.2.

## Run from source

Requires Python 3.10 or newer. From this directory:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
meow
```

Use `meow --help` for scriptable operations, `meow --doctor` for diagnostics,
and `meow --no-animation` for reduced motion. The original `llm-forensics`
command remains available.

## Capabilities

Scan known artifact locations, acquire evidence into a new case, analyze supported
JSON/SQLite/log formats, export reports and conversations, verify integrity,
compare cases, package cases, and run synthetic validation.

Recovery depends on which artifacts still exist and the runner version. No
findings does not establish absence of LLM use. Deleted-record recovery is
experimental; recovered candidates are not automatically proven conversations.
Integrity manifests are unsigned and do not independently prove authenticity.

The tool uses existing permissions. Full Disk Access is a separate macOS setting;
it never collects passwords or grants itself permissions.

## Tests and builds

```sh
python3 -m unittest discover -s tests
python3 build_cli.py
python3 -m pip install -r build-requirements.txt
python3 build_native.py
```

Native builds must be made on the target platform. Current distribution work
focuses on macOS Apple Silicon. Same-host testing is not independent deployment
certification. Windows/Linux and Intel Mac deployment are not certified.

## Distribution status

No public Homebrew tap or signed/notarized release is available yet. The packaging
folder contains a local installer intended for a complete extracted native release
and a formula generator requiring explicit hosting URLs. Do not run the installer
from this source tree. Existing private evidence and development scan reports are
not included in this repository.

## License

A distribution license has not yet been selected. Public availability alone does
not grant an open-source license. A license will be added after the owner chooses it.
