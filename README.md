# meowrtuary

```text
 /\_/\
( o.o )   meowrtuary  1.5.0
```

A macOS command-line tool for discovering, acquiring and reviewing local LLM
artifacts from Ollama, LM Studio and llama.cpp. Use its guided menu or scriptable
commands to preserve evidence, generate searchable reports and verify case integrity.

## Install

For **macOS Apple Silicon (ARM64)** with Homebrew installed:

```sh
brew tap precisefull47/meowrtuary
brew install meowrtuary
meow
```

Update an existing installation:

```sh
brew update
brew upgrade meowrtuary
meow --version
```

The native package includes Python. No model download, API key or paid developer
membership is needed to run it. Internet access is needed for installation;
analysis operates locally. Intel Macs and Windows/Linux execution are not verified.

Alternatively download the archive and matching checksum from
[Releases](https://github.com/Precisefull47/meowrtuary/releases), verify the checksum,
and run the extracted `bin/llm-forensics --menu`. Keep its `_internal` directory intact.
See the [user guide](USER_GUIDE.md) for manual installation and troubleshooting.

## What it does

- **Scan:** discover supported artifacts in selected local locations.
- **Analyze:** parse acquired evidence and optionally capture originals into a case.
- **Reports:** browse conversations, evidence and timeline; export JSON, HTML and CSV.
- **Verify:** check acquired-file hashes or the integrity of the complete sealed case.
- **Compare:** compare two case results without rewriting either.
- **Package:** create a separate shareable case bundle.
- **Validate:** run controlled built-in fixtures and inspect environment diagnostics.

The menu groups these operations into Scan, Analyze, Open a case, Case tools and
Diagnostics. Arrow keys, numbered choices and the on-screen shortcuts are supported.
Use `meow --no-animation` for a quiet startup.

## Command-line examples

```sh
meow --help
meow --doctor
meow --live --acquire --format both --timeline --output ./new-case
meow /path/to/acquired-evidence --source-os macos --acquire --format both --output ./new-analysis
meow --verify-case ./new-case
meow --verify-package ./new-case
meow --self-test --output ./new-self-test
```

Choose a new output directory outside the evidence source. Guided acquisitions
use the device name and acquisition timestamp for default case-folder names;
original evidence filenames remain intact. Reports show source paths, record
locators and collection gaps so findings can be traced to their origin.

## Scope and trust

This is artifact analysis, not guaranteed recovery of every conversation or deleted
file. Retention differs between runners and modes. Prompts may survive without
replies. Full Disk Access is granted separately in macOS; the tool cannot bypass
permissions. Live acquisition is not an atomic disk image. Hashes detect changes
relative to a manifest; they are not independent proof of authenticity.

Read [supported use and recovery limits](SUPPORTED_USE.md), the
[verification matrix](VALIDATION.md) and [release notes](RELEASE_NOTES.md).
The executable is not Developer ID signed or notarized. Native file-picker
acceptance and independent physical-Mac deployment remain unverified.

## Development

Python 3.13+ is required for the development QA workflow. On macOS ARM64, install
`build-requirements.txt` in a virtual environment and run:

```sh
python3 -m unittest discover -s tests
python3 qa/run.py --allow-missing-external
```

The second command builds and tests fresh packages in isolated worktrees. Its
successful automated gate does not mark external acceptance passed. See
[QA instructions](qa/README.md). QA is development tooling, separate from the
installed forensic executable. Never use real evidence as writable test fixtures.

## License

Original code is [MIT licensed](LICENSE). Bundled runtime components retain their
own licenses; see [third-party notices](packaging/release-docs/THIRD_PARTY_NOTICES.md).
