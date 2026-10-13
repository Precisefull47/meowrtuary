# meow installation and distribution

The `meow` command opens the approved interactive menu when attached to a terminal.
Arguments pass directly to the native executable (`meow --help`, `meow --doctor`,
`meow --no-animation`). Redirected execution preserves the existing CLI behavior.
The original `llm-forensics` command remains compatible.

## Local installation from a trusted release

Verify the archive SHA-256 against the separately supplied trusted checksum, extract
it, then run from the extracted directory:

```sh
sh install-local.sh
# Or choose an absolute prefix:
sh install-local.sh "$HOME/.local"
meow
```

The installer keeps the complete native bundle in
`~/.local/share/meowrtuary/1.4.2/bin` and links `~/.local/bin/meow` to it.
No separate Python, sudo, shell-profile edits, automatic scans or background service.
If `~/.local/bin` is not on PATH, add `export PATH="$HOME/.local/bin:$PATH"` to your
shell configuration. The installer reports this rather than changing your profile.
It refuses to overwrite an existing command or version directory.

For a manual upgrade, retain the old version directory, remove only the `meow`
symlink after checking its target, then install the new release. Roll back by
restoring that link. For uninstall, remove that link and the installed version
folder; reports and evidence live elsewhere and must not be deleted.

## Prepare a Homebrew tap

`homebrew_formula.py` generates `Formula/meowrtuary.rb` from an archive, explicit
HTTPS download URL, HTTPS project homepage and version. It computes the real SHA-256.
It never uploads anything. Run `python3 packaging/homebrew_formula.py --help` for
arguments. `file://` is supported for local tests only. The example under
validation/meow-install uses an intentionally invalid placeholder homepage and is
not a published distribution formula.

Once a repository and immutable release URL have been selected and publishing is
approved, generate the formula with those real URLs and put it in a Homebrew tap.
Then users can run `brew tap OWNER/TAP`, `brew install meowrtuary`, and `meow`.
Homebrew owns installation, upgrades and uninstall for that route. Remove any
manual `meow` installation first to avoid PATH shadowing.

The formula is macOS ARM64-only, installs the full bundle into libexec, and links
only `meow` into bin. Its test runs version, diagnostics, and synthetic validation.
Reference: https://docs.brew.sh/Formula-Cookbook

## Status and limitations

Local installation and native launch are tested on the development Mac, including
prefixes with spaces and collision refusal. Homebrew installation, formula tests, same-version reinstall, and uninstall
passed using a temporary local-only tap. Public download, upgrades between different
versions, notarization, and independent-Mac deployment remain unvalidated. The release is not Developer ID signed/notarized. Do not disable macOS
protections to install it. Full Disk Access remains a separate user-granted setting.
