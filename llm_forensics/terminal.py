"""Plain-text terminal presentation; evidence values are escaped before display."""
import shutil
import textwrap
from . import __version__

DISPLAY_NAME = 'meowrtuary'
CAT_LOGO = [' /\\_/\\', '( o.o )']
COMMAND_NAME = 'llm-forensics'


def terminal_width():
    return max(20, shutil.get_terminal_size((80, 24)).columns - 1)


def brand_lines(width=80):
    identity=f'{DISPLAY_NAME}  v{__version__}'
    logo=CAT_LOGO
    if width>=32:
        size=max(map(len,logo))
        return ['  '+line.ljust(size)+('   '+identity if i==len(logo)//2 else '')
                for i,line in enumerate(logo)]
    return textwrap.wrap(identity,max(1,width),break_on_hyphens=False)


def banner(width=None):
    return '\n'.join(brand_lines(width or terminal_width()))


def artifact_table(findings, live=False, width=None):
    width = width or terminal_width()
    # Put source paths below each row so long acquisition paths cannot break columns.
    rows = [(str(i), ascii(f['runner'])[1:-1], ascii(f['artifact_type'])[1:-1], ascii(f['status'])[1:-1]) for i, f in enumerate(findings, 1)]
    headers = ('#', 'RUNNER', 'ARTIFACT', 'STATUS')
    sizes = [max([len(headers[i])] + [len(row[i]) for row in rows]) for i in range(4)]
    tabular = sum(sizes) + 6 <= width
    lines = []
    if tabular:
        lines.append('  '.join(h.ljust(n) for h, n in zip(headers, sizes)).rstrip())
        lines.append('  '.join('-' * n for n in sizes))
    for row, finding in zip(rows, findings):
        if tabular:
            lines.append('  '.join(v.ljust(n) for v, n in zip(row, sizes)).rstrip())
        else:
            for label, value in zip(headers, row):
                lines.extend(textwrap.wrap(f'{label}: {value}', width, subsequent_indent='  '))
        source = finding.get('original_source_path') or finding['source_path' if live else 'evidence_relative_path']
        lines.extend(textwrap.wrap('  Source: ' + ascii(source), width, subsequent_indent='          ', break_on_hyphens=False))
        lines.append('')
    if not rows:
        lines.append('No supported artifacts found in the selected scope.')
    return '\n'.join(lines)


def coverage_text(coverage, width=None):
    width=width or terminal_width()
    lines=[f"Coverage: {coverage['status'].upper()}",coverage['meaning'],
        f"Locations recorded: {len(coverage['locations'])} | Gaps: {len(coverage['gaps'])}"]
    for gap in coverage['gaps'][:8]:
        source=gap.get('path',gap.get('source_path')) or 'Scope'
        lines.append('  '+ascii(str(gap.get('status','unknown')))[1:-1]+': '+ascii(str(source)))
    if len(coverage['gaps'])>8:lines.append('  Additional gaps are listed in the report.')
    return '\n'.join(piece for line in lines for piece in textwrap.wrap(line,width,subsequent_indent='  ',break_on_hyphens=False))


def motion_enabled():
    """Motion is opt-out independently of color; never animate redirected output."""
    import os
    import sys
    return (sys.stdout.isatty() and os.environ.get('TERM', '') not in ('', 'dumb')
            and not any(os.environ.get(key, '').lower() not in ('', '0', 'false')
                        for key in ('LLF_REDUCED_MOTION', 'LLF_NO_ANIMATION')))


def fit_line(text, width=None):
    """Clip a single status line before it reaches the terminal's wrap column."""
    import unicodedata
    width = max(1, width if width is not None else terminal_width())
    result = []; used = 0
    for char in str(text):
        if not char.isprintable():
            char = ' '
        size = 0 if unicodedata.combining(char) else 2 if unicodedata.east_asian_width(char) in ('W', 'F') else 1
        if used + size > width:
            break
        result.append(char); used += size
    return ''.join(result)
