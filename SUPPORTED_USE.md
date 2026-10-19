# Supported use — meowrtuary 1.5.0

Supported configurations and verification scope. Updated 19 October 2026.

## Execution scope

Local macOS Apple Silicon (ARM64). The current validation host is macOS 27.0.1,
build 26A434. Intel Macs, earlier macOS versions, Windows/Linux execution and a
second physical Mac are NOT TESTED for this version. Python is bundled in the
native package. Source builds use Python 3.14.7 and pinned build-requirements.txt.

The tool reads existing files; it does not start runners, submit prompts, collect
account passwords or query model servers. Validation experiments start runners
separately in isolated profiles. Known-path discovery is not a whole-disk search.
Use explicit evidence paths for relocated profiles. LM Studio home pointers are
preserved but not automatically followed. All-users and external volumes require
explicit scope selection and suitable access.

## Runner observations and limits

The current controlled experiment environments are Ollama 0.34.0, LM Studio
0.4.25+1 with its llama.cpp 2.47.0 runtime, and llama.cpp build 11146 (7fe450e19).
A local Smollm2 135M GGUF is the common test model. Exact final-package recovery
results, commands and hashes are in the release verification record;
installed versions alone are not evidence of successful recovery.

* Ollama CLI history can retain entered prompts. It is not a full conversation
  transcript and need not retain generated replies. HTTP API inference alone
  need not create prompt-history artifacts. Model metadata proves presence, not
  authorship or execution. Desktop SQLite and saved-session formats have separate
  parsers; do not extrapolate a CLI test to every desktop version.
* LM Studio supported conversation JSON can retain role-labelled text and message
  versions. Unsupported blocks are reported separately. A stored version is not
  necessarily the currently selected message. Read version flags and source links.
* llama.cpp optional recognized logs expose raw text, not authenticated roles or
  timestamps. Session v10 caches expose token IDs and partially parsed state.
  Conditional GPT-2-vocabulary decoding requires the supplied matching GGUF;
  the cache itself does not authenticate that association. Unsupported tokenizers
  and cache versions are not silently treated as decoded conversations.
* Historical SQLite residue recovery is experimental and opt-in. Intact candidate
  records may be superseded rather than deleted. No raw APFS deleted-file recovery,
  SSD/TRIM recovery guarantee, or deletion-time attribution is provided. Readable
  Trash files are existing artifacts, not proof of raw deleted-data recovery.

## Permissions and evidence handling

Run with the examiner's ordinary permissions. For authorized access to protected
locations, macOS may require Full Disk Access for the launching application, then
an application restart. The tool can show settings guidance; it cannot grant
access, bypass TCC, or guarantee access to every descendant. A password or sudo
is not a substitute. Permission gaps must remain visible in the report.

Prefer read-only acquired evidence. Live reads can affect access times and cannot
produce an atomic snapshot of an actively changing filesystem. Unstable SQLite
capture groups are quarantined. Preserve raw filenames, hashes, source paths and
record locators. A zero-result report proves only that supported artifacts were
not found in the readable selected scope.

Manifests are unsigned: verification detects changes relative to the manifest,
not independent authenticity. Keep original cases sealed. Reports and bundles
may contain sensitive prompts and credentials copied as raw evidence; bundles
are not encrypted. Store and share them through approved channels.

## Reports and UI

New reports have Overview, Conversations, Evidence and Timeline sections. HTML
hides empty fields; JSON preserves original values. Timeline HTML limits each
dated/undated group to 500 rows; use JSON/CSV for all events. File modification
times are distinct from interaction times. Report search is artifact-level,
not a claim that every message matches. Historical residue is separate from the
Conversations view. Print this section prints the selected view with current filters and expanded
details. A printed scope notice and match counts identify the subset. Closed
raw-record details remain closed; expand a detail before printing to include it.
Use structured exports for complete records. Print output is a presentation,
not a new evidence seal.

The guided menu uses arrows or numbered selections. Confirmations require an
explicit choice; Back/Cancel do not authorize capture. --no-animation and
--reduced-motion suppress startup motion. NO_COLOR and plain-terminal fallbacks
are supported. Noninteractive commands retain their exit codes and JSON output.

## Installation and troubleshooting

Keep the extracted native binary beside its _internal folder. Run
`./bin/llm-forensics --version`, `--doctor`, then `--self-test --output NEW_FOLDER`.
The manual installer refuses existing versions and conflicting commands. Use
`type -a meow` to identify an older manual command shadowing Homebrew. Do not
replace a validated release in place or regenerate reports inside a sealed case.

The executable is not Developer ID signed or notarized. Follow organizational
installation policy; do not disable macOS security controls. Another physical
Mac's installation/permissions workflow remains a release acceptance gate.

If capture fails, retain the partial case and manifest, inspect reported gaps,
and retry into a new output directory. If the selected output volume disconnects
or changes, choose it again; the tool must not silently use a replacement.

## Verification status

See VALIDATION.md for executed checks and outstanding native UI and independent-Mac checks. A versioned release does not certify untested environments.
