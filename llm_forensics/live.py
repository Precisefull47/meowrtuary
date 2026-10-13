"""Automatic known-location discovery, with explicit visibility of skipped scopes."""
import os
import platform
from pathlib import Path
from datetime import datetime, timezone
from . import __version__
from .traversal import Budget
from .scanner import scan, is_link_or_reparse


def host_os():
    value={'Darwin':'macos','Windows':'windows','Linux':'linux'}.get(platform.system())
    if not value: raise ValueError('Live discovery supports Windows, macOS and Linux')
    return value


def known_locations(profile, system, include_trash=False):
    paths=[profile/'.ollama',profile/'.lmstudio',profile/'.cache/lm-studio',profile/'.lmstudio-home-pointer']
    if system in {'macos','linux'}:
        paths.extend([profile/'.bash_history',profile/'.zsh_history'])
    if system=='windows':
        paths.extend([profile/'AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt',
                      profile/'AppData/Roaming/Microsoft/PowerShell/PSReadLine/ConsoleHost_history.txt'])
    if system=='macos':
        paths.append(profile/'Library/Application Support/Ollama')
        paths.extend([profile/'Library/Preferences/com.electron.ollama.plist',
                      profile/'Library/Preferences/ai.elementlabs.lmstudio.plist',
                      profile/'Library/Logs/LM Studio',
                      profile/'Applications/Ollama.app/Contents/Info.plist',
                      profile/'Applications/LM Studio.app/Contents/Info.plist'])
        if include_trash: paths.append(profile/'.Trash')
    if system=='windows': paths.append(profile/'AppData/Local/Ollama')
    return paths


def discover(all_users=False, include_trash=False):
    system=host_os(); profiles=[Path.home()]; issues=[]
    if include_trash and system!='macos':raise ValueError("--include-trash currently supports macOS only")
    if all_users:
        parent=Path(os.environ.get('SystemDrive','C:')+'/Users') if system=='windows' else Path('/Users' if system=='macos' else '/home')
        try:
            profiles.extend(p for p in parent.iterdir() if p.is_dir() and not is_link_or_reparse(p))
        except OSError as exc:
            issues.append({'path':str(parent),'status':'profile_discovery_failed','detail':str(exc)})
        if system=='linux': profiles.append(Path('/root'))
    candidates=[]
    for profile in dict.fromkeys(profiles): candidates.extend(known_locations(profile,system,include_trash))
    if system=='macos': candidates.extend([Path('/Applications/Ollama.app/Contents/Info.plist'),Path('/Applications/LM Studio.app/Contents/Info.plist')])
    if system=='linux': candidates.extend([Path('/usr/share/ollama/.ollama'),Path('/etc/systemd/system')])
    return system,list(dict.fromkeys(candidates)),issues


def scan_locations(locations, system, output, max_bytes, initial_issues=(), recover_deleted=False, optional_sources=None):
    optional={str(p.absolute()) for p in (locations if optional_sources is None else optional_sources)}
    now=lambda:datetime.now(timezone.utc).isoformat()
    report={'tool':'Local LLM Forensics','version':__version__,'evidence_root':'Live known-location scan',
            'scan_started_utc':now(),'analysis_host_os':platform.system(),'source_os':system,'source_os_basis':'live host',
            'findings':[],'issues':list(initial_issues),'files_considered':0,'discovery_coverage':[], 'locations':[],
            'limitations':['Live known-location discovery is not a full-disk forensic acquisition.',
            'Custom paths, external volumes, GUI databases, encrypted storage and deleted data may be missed.',
            'Live files can change during reading; reads can affect filesystem access times.',
            'No findings does not establish absence of local LLM use.']}
    # Check every boundary before reading evidence or creating any output.
    for location in locations:
        resolved=location.resolve()
        if output==resolved or resolved in output.parents:
            raise ValueError('Output must be outside all discovered evidence locations')
    seen=set();budget=Budget()
    for location in locations:
        entry={'path':str(location),'status':'pending'};report['locations'].append(entry)
        try:
            if is_link_or_reparse(location):
                entry['status']='symlink_skipped';continue
            if not location.is_dir() and not location.is_file():
                entry['status']='not_a_file_or_directory';continue
            result=scan(location,max_bytes,system,recover_deleted=recover_deleted,traversal_budget=budget)
            entry['status']='scanned_with_issues' if result['issues'] else 'scanned'
            entry['candidate_artifacts']=len(result['findings'])
            report['files_considered']+=result['files_considered']
            report['issues'].extend(result['issues'])
            report['discovery_coverage'].extend(dict(r,scan_root=str(location)) for r in result['discovery_coverage'])
            for finding in result['findings']:
                if finding['source_path'] in seen: continue
                seen.add(finding['source_path'])
                finding['id']=f"artifact-{len(report['findings'])+1}"
                finding['scan_root']=str(location)
                report['findings'].append(finding)
        except FileNotFoundError:
            entry['status']='not_found' if str(location.absolute()) in optional else 'missing_explicit_scope'
            if entry['status']=='missing_explicit_scope':report['issues'].append({'path':str(location),'status':entry['status'],'detail':'Explicit evidence location does not exist'})
        except OSError as exc:
            entry['status']='inaccessible'
            report['issues'].append({'path':str(location),'status':'inaccessible','detail':str(exc)})
    report['traversal']=budget.snapshot()
    report['scan_finished_utc']=now()
    return report
