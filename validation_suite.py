"""Repeatable synthetic runner/path validation; never reads the analyst's profile."""
import argparse
from collections import Counter
import hashlib
import json
import platform
from pathlib import Path
import tempfile

from llm_forensics import __version__
from llm_forensics.scanner import scan


def run_suite():
    results=[]
    for system in ('windows','macos','linux'):
        prefix='home/Analyst' if system=='linux' else 'Users/Analyst'
        for runner in ('ollama','lm_studio','llama_cpp'):
            with tempfile.TemporaryDirectory(prefix='llmf-ground-truth-') as directory:
                root=Path(directory)
                marker=f'SYNTHETIC_{system}_{runner}'
                if runner=='ollama':
                    relative=f'{prefix}/.ollama/history'
                    payload=(marker+'\n').encode()
                    expected=[marker]
                elif runner=='lm_studio':
                    relative=f'{prefix}/.lmstudio/conversations/fixture.json'
                    expected=[marker+'_original',marker+'_edited',marker+'_response']
                    payload=json.dumps({'messages':[{'versions':[
                        {'role':'user','content':[{'type':'text','text':expected[0]}]},
                        {'role':'user','content':[{'type':'text','text':expected[1]}]}]},
                        {'versions':[{'role':'assistant','steps':[{'content':[{'type':'text','text':expected[2]}]}]}]}]}).encode()
                else:
                    relative=f'{prefix}/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt' if system=='windows' else f'{prefix}/.zsh_history'
                    command=f'& "C:\\Tools\\llama-cli.exe" -p "{marker}"' if system=='windows' else f'./llama-cli -p "{marker}"'
                    payload=('echo unrelated\n'+command+'\nllama-cli-not-a-runner --help\n').encode()
                    expected=[command]
                source=root/relative;source.parent.mkdir(parents=True);source.write_bytes(payload)
                # Plausible conversation text outside supported paths must not become a finding.
                (root/'unrelated.json').write_text('{"role":"user","content":"NEGATIVE_CONTROL"}',encoding='utf-8')
                report=scan(root,source_os=system)
                findings=report['findings']
                actual=[r['text'] for f in findings for r in f['observations'] if 'text' in r]
                wanted=Counter(expected);found=Counter(actual)
                missing=list((wanted-found).elements());unexpected=list((found-wanted).elements())
                unchanged=source.read_bytes()==payload
                provenance=len(findings)==1 and findings[0]['sha256']==hashlib.sha256(payload).hexdigest() and all(r.get('record_locator') for r in findings[0]['observations'])
                results.append({'source_os_layout':system,'runner':runner,'artifact':relative,
                    'expected_records':len(expected),'extracted_records':len(actual),'missing':missing,'unexpected':unexpected,
                    'source_unchanged':unchanged,'provenance_passed':bool(provenance),
                    'passed':not missing and not unexpected and unchanged and bool(provenance) and not report['issues']})
    return {'tool_version':__version__,'execution_host':platform.system(),'fixture_type':'synthetic',
        'limitations':'Simulated OS paths and schemas only. Not real runner execution, OS certification, or an estimate of general forensic accuracy.',
        'cases':results,'passed':all(r['passed'] for r in results)}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,help='Optional new JSON file; never overwritten')
    args=parser.parse_args()
    result=run_suite()
    if args.output:
        with args.output.open('x',encoding='utf-8') as handle:json.dump(result,handle,indent=2)
    print(f"Synthetic validation: {sum(r['passed'] for r in result['cases'])}/{len(result['cases'])} passed on {result['execution_host']}")
    if not result['passed']:raise SystemExit(1)


if __name__=='__main__':main()
