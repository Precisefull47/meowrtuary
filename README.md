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

## Install on macOS Apple Silicon

```sh
brew tap precisefull47/meowrtuary
brew install meowrtuary
meow
```

Updates: `brew upgrade meowrtuary`. Remove: `brew uninstall meowrtuary`.
The formula downloads the full native bundle from this repository's GitHub Releases
and verifies its SHA-256 checksum. No separate Python installation is required.
Intel Macs and Linux are not supported by this formula.

This is v1 Preview (internal version 1.4.2), not a production-certified release.
The executable is not Developer ID signed or notarized. Independent-Mac deployment
remains unverified. Full Disk Access is a separate macOS user setting when needed.
Private evidence and development scan reports are not included.

## License

MIT License. Copyright (c) 2026 precisefull47. See LICENSE.
Bundled third-party runtimes retain their separate upstream licenses.
