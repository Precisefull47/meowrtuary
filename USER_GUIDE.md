# meowrtuary user guide

## Install, update and launch

Use the Homebrew commands in README.md. Launch `meow` for the interactive menu,
`meow --help` for all CLI flags, and `meow --version` to check the executable version.
The supported distribution is macOS ARM64. Do not copy only the binary out of its
native bundle: its adjacent `_internal` directory is required.

For manual downloads, put the archive and `.sha256` file in the same directory:

```sh
shasum -a 256 -c meowrtuary-1.5.0-macos-arm64.tar.gz.sha256
tar -xzf meowrtuary-1.5.0-macos-arm64.tar.gz
cd meowrtuary-1.5.0-macos-arm64
./bin/llm-forensics --version
./bin/llm-forensics --doctor
./bin/llm-forensics --menu
```

The optional `./install-local.sh` installs into `~/.local` without sudo or editing
your shell configuration. Add `~/.local/bin` to PATH yourself if needed. The installer
refuses to overwrite an existing command or version. Prefer one installation method.

If Homebrew updates but `meow --version` stays old, run `type -a meow`. An older
`~/.local/bin/meow` may precede Homebrew in PATH. Inspect it before moving or removing
it; you can launch `$(brew --prefix meowrtuary)/bin/meow` explicitly. Never delete
case folders to fix an installation. `brew uninstall meowrtuary` removes the formula,
not independently stored cases.

## Before acquisition

Confirm authorization and evidence scope. Prefer acquired read-only data where
possible. Choose an output directory outside the input tree with sufficient free
space. Preserve existing cases and generate derived reports into a new directory.
Close the runner when an operationally appropriate stable acquisition is needed;
a live changing profile may produce incomplete captures.

Run `meow --doctor` and review scope/access warnings. For protected locations such
as Trash, enable Full Disk Access for the application launching the tool in
System Settings → Privacy & Security → Full Disk Access, then restart that
application. The tool offers guidance when access probes fail. It cannot enable
permissions itself, and a passing probe is not proof that every descendant is
readable. Do not enter your account password into meowrtuary or disable security
controls. An administrator password or sudo does not replace Full Disk Access.

## Guided workflow

Choose Scan to inspect this Mac, or Analyze for a selected evidence file/folder.
Select standard or advanced settings, choose scope and output, then review the
confirmation. Back changes the preceding choice; Cancel abandons the workflow.
Blank input does not authorize acquisition. Arrow navigation applies to choices;
text fields accept typed paths. File pickers depend on the macOS UI environment.

The default case-folder name includes a sanitized device name and acquisition
timestamp. Input evidence filenames are preserved. Completion shows the case and
report locations. On cancellation or failure, retain any partial output and read
its status before retrying into a new directory.

Open a case to review existing results. Case tools provide verification, comparison
and packaging. Diagnostics includes environment checks and synthetic validation.
Use the horizontal shortcut footer for available Back, Cancel and Quit actions.
`--no-animation` or `--reduced-motion` disables startup motion; `NO_COLOR` disables
colors. Redirected and machine-readable output avoid decorative animation.

## Scriptable operations

```sh
meow --live --include-trash --acquire --format both --timeline --export-conversations --output ./new-case
meow /path/to/evidence --source-os macos --acquire --format both --output ./new-analysis
meow --export-reports ./new-case --output ./new-report-export
meow --verify-case ./new-case
meow --verify-package ./new-case
meow --compare ./before-case ./after-case --output ./new-comparison
meow --bundle-case ./new-case --output ./new-bundle
meow --self-test --output ./new-validation
```

Consult `--help` for opt-in recovery, explicit runner locations and all-users scope.
Do not enable advanced options without understanding their coverage and limitations.
`--strict` returns exit code 3 for incomplete analysis. Preserve exit status and logs
in scripts; an empty finding set does not establish absence of local LLM activity.

## Reading and sharing reports

Overview summarizes the case; Conversations shows supported retained dialogue;
Evidence links findings to source records; Timeline distinguishes recorded events
from filesystem timestamps. Search is artifact-level. Expand details when needed.
Empty display fields are hidden while structured exports preserve values.

Print this section includes the selected view, filters and expanded details, with
a printed scope notice. Closed raw-record details stay closed. Timeline HTML shows
up to 500 rows per dated/undated group; use JSON/CSV for complete events. A report
is a presentation of evidence and does not independently authenticate it.

Verify captured-file hashes with `--verify-case`. Use `--verify-package` to verify
sealed case integrity. Keep original sealed cases unchanged; exports and bundles
belong in separate new destinations. Bundles are not encrypted and may contain
sensitive prompts, paths or credentials captured in raw evidence.

## Troubleshooting

- Permission denied: inspect the exact coverage gap, grant authorized access to the
  launching application and restart it. Retry into a new case.
- Missing conversations: confirm runner/version/profile and retention mode. A CLI
  history or API request may not retain replies or any conversation at all.
- Unsupported cache: retain the raw artifact; do not assume token decoding equals
  an authenticated conversation. See SUPPORTED_USE.md.
- Output storage disconnected/replaced: select the destination again. Do not reuse
  a path whose volume identity changed during an operation.
- Verification failure: preserve the failing case and logs. Compare against the
  trusted acquisition record rather than resealing to hide the mismatch.
- macOS installation warning: follow organizational policy for unsigned software;
  this release is not Developer ID signed or notarized.
