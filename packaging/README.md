# Distribution maintenance

Build on macOS ARM64 using the pinned build requirements. Run the complete QA
workflow before publication. `build_native.py` produces the native runtime;
`packaging/build_candidate.py` wraps it in an immutable, versioned distribution
archive under dist/distribution. The script refuses to overwrite an archive.
`build_release.py` creates the separate source/portable/native QA validation bundle.

Update llm_forensics/__init__.py, pyproject.toml, release notes and packaged docs
consistently. Copy current user documentation into packaging/release-docs before
building. Rebuild and revalidate whenever included source or docs change.

Generate the Homebrew formula with packaging/homebrew_formula.py using the exact
archive, HTTPS release URL, homepage and version. Test the formula before publishing,
then verify the downloaded public asset checksum and run Homebrew's formula test.
Never replace an existing release asset with different bytes at the same URL.

Publication requires explicit owner authorization. Keep local QA reports and private
evidence out of Git. A successful local build does not certify another Mac or grant
macOS permissions. Review bundled licenses when updating runtime dependencies.
