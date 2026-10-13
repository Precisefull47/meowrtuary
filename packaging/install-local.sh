#!/bin/sh
# Install a trusted, extracted native release without sudo or shell-profile edits.
set -eu
release=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
prefix=${1:-"$HOME/.local"}
case "$prefix" in /*) ;; *) echo 'Installation prefix must be absolute.' >&2; exit 2;; esac
[ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ] || { echo 'Requires macOS Apple Silicon.' >&2; exit 2; }
[ -x "$release/bin/llm-forensics" ] && [ -d "$release/bin/_internal" ] || { echo 'Incomplete release bundle.' >&2; exit 1; }
# Read a packaging-generated, non-executable version marker.
version=$(cat "$release/VERSION")
case "$version" in ''|*[!0-9.]*|.*|*..*) echo 'Invalid release version.' >&2; exit 1;; esac
root="$prefix/share/meowrtuary"
target="$root/$version"
command="$prefix/bin/meow"
if [ -e "$command" ] || [ -L "$command" ]; then
  echo "Refusing to overwrite existing command: $command" >&2; exit 1
fi
if [ -e "$target" ] || [ -L "$target" ]; then
  echo "Installation already exists: $target" >&2; exit 1
fi
mkdir -p "$root" "$prefix/bin"
stage=$(mktemp -d "$root/.install.XXXXXX")
trap 'rm -rf -- "$stage"' EXIT HUP INT TERM
cp -R "$release/bin" "$stage/bin"
"$stage/bin/llm-forensics" --doctor >/dev/null
mv "$stage" "$target"
ln -s "$target/bin/llm-forensics" "$command"
printf 'Installed: %s\nRun: meow\n' "$command"
case ":$PATH:" in *":$prefix/bin:"*) ;; *) printf 'Add this directory to your shell PATH: %s/bin\n' "$prefix";; esac
