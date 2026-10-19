# meowrtuary 1.5.0

## Changes

- Dashboard reports with Overview, Conversations, Evidence and Timeline views,
  search and expandable details. Empty display values are omitted.
- Selected-section printing honors filters and expanded details, identifies the
  printed subset and avoids automatically expanding all raw records.
- Narrow report layouts keep timeline columns readable with contained scrolling.
- Default guided case names include the device name and acquisition timestamp;
  original evidence filenames are preserved.
- Compact cat branding, consistent navigation spacing, arrow shortcuts and a
  horizontal footer. Startup motion can be disabled.
- Explicit confirmations reject blank/invalid input. Output-path identity checks
  prevent silent reuse of a disconnected or replaced destination.
- Updated packaged-workflow, report, naming, navigation and integrity regression
  coverage; reusable isolated QA with machine-readable results.
- Expanded installation, usage, permission, recovery and verification documentation.

## Distribution

macOS Apple Silicon native archive with bundled Python, checksum and per-file
manifest. The GitHub release and Homebrew formula use the same 1.5.0 archive.
Older releases remain available unchanged. Reports and case evidence are never
included in the download.

## Known limits

No Developer ID signature or notarization. Actual native Terminal/file-picker
acceptance and independent physical-Mac deployment remain unverified. Runner
retention varies; recovery is not guaranteed. See SUPPORTED_USE.md and VALIDATION.md
for exact environments and the distinction between PTYs, simulated UI, browser
checks and controlled real-runner evidence.
