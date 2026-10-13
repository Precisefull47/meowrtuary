# meowrtuary — v1 Preview

Internal version: 1.4.2. Platform: macOS Apple Silicon (ARM64).

A terminal tool for examining local artifacts from Ollama, LM Studio and llama.cpp.
Includes acquisition, reporting, case comparison, integrity checks, packaging,
experimental deleted-record recovery, and synthetic validation.

## Install

Verify the archive against its separately obtained trusted SHA-256 checksum, then
extract it. From the extracted folder:

```sh
sh install-local.sh
meow
```

This installs the complete native bundle under `~/.local/share/meowrtuary/1.4.2`
and a `~/.local/bin/meow` symlink. No Python installation is required.
If your shell cannot find `meow`, add `~/.local/bin` to PATH. Existing commands
and installed version directories are never overwritten. For immediate use without
installation: `./bin/llm-forensics`.

Useful commands: `meow --help`, `meow --doctor`, `meow --no-animation`.
For an isolated synthetic test:
`meow --self-test --output /absolute/path/to/a/new-validation-folder`.

To remove a manual installation, verify and remove the `~/.local/bin/meow` symlink
and the corresponding version directory. Keep evidence and reports separately.
The installer refuses upgrades in place; retain the previous version for rollback,
remove only its command symlink, then install the new version.

## Scope

Use only on data you are authorized to examine. The tool never collects passwords.
Full Disk Access is granted separately through macOS settings when needed. Reading
a live filesystem can affect metadata; prefer acquired read-only evidence.

The presence and recoverability of conversations depends on runner version and
remaining data. No findings does not prove absence of use. Deleted records are
experimental candidates. Unsigned manifests detect changes relative to the
manifest; they do not independently establish authenticity.

This preview is tested on the development Mac. Independent-Mac installation,
Intel Macs, and earlier macOS versions remain unverified. The executable is not
Developer ID signed or notarized. Do not disable system protections to run it.

The original project code is MIT licensed, copyright 2026 precisefull47.
Bundled runtime components retain their own licenses; see THIRD_PARTY_NOTICES.md.
