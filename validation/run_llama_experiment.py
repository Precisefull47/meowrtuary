"""Run an explicitly selected local llama-completion binary/model in a new case.

Examiner stdout and ground truth stay outside scan inputs. No downloads, shell
execution, model changes, or removal of original artifacts are performed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from llm_forensics.scanner import scan
from llm_forensics.report import render_html


def digest(path):
    result=hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda:handle.read(1024*1024),b''):result.update(block)
    return result.hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runner',type=Path,required=True)
    parser.add_argument('--model',type=Path,required=True)
    parser.add_argument('--case',type=Path,required=True)
    parser.add_argument('--cache-all',action='store_true',help='Include generated tokens in the logged experiment session')
    args=parser.parse_args()
    runner=args.runner.resolve(strict=True);model=args.model.resolve(strict=True);case=args.case.resolve()
    if case.exists():parser.error('Use a new case directory')
    case.mkdir(parents=True);examiner=case/'examiner';examiner.mkdir()
    prompt='LLMF_CONTROLLED_LIGHTHOUSE_7F31: Explain what a lighthouse does in one sentence.'
    common=[str(runner),'-m',str(model),'-p',prompt,'-n','48','-c','512','--seed','123','--no-conversation','--device','none','--fit','off','--no-op-offload','--no-kv-offload']
    version=subprocess.run([str(runner),'--version'],capture_output=True,text=True,check=True,timeout=15)
    ground={'prompt':prompt,'runner_version':version.stdout+version.stderr,'runner_sha256':digest(runner),'model_sha256':digest(model),'commands':[]}
    for name,logging in [('without-logging',False),('with-logging',True)]:
        folder=case/name;folder.mkdir()
        command=common+(['--log-file',str(folder/'llama.log'),'--prompt-cache',str(folder/'session.cache')] if logging else [])
        if logging and args.cache_all:command.append('--prompt-cache-all')
        ground['commands'].append(command)
        with (examiner/(name+'-stdout.txt')).open('w') as out,(examiner/(name+'-stderr.txt')).open('w') as err:
            subprocess.run(command,cwd=folder,stdout=out,stderr=err,check=True,timeout=120)
    (examiner/'ground-truth.json').write_text(json.dumps(ground,indent=2))
    copied=case/'after-log-removal';shutil.copytree(case/'with-logging',copied)
    (copied/'llama.log').unlink()  # Only the disposable copy is changed.
    results={}
    for name in ('without-logging','with-logging','after-log-removal'):
        folder=case/name;before={p.name:digest(p) for p in folder.iterdir() if p.is_file()}
        report=scan(folder)
        target=case/(name+'-report');target.mkdir()
        (target/'report.json').write_text(json.dumps(report,indent=2))
        (target/'report.html').write_text(render_html(report))
        assert before=={p.name:digest(p) for p in folder.iterdir() if p.is_file()}
        results[name]={'files':before,'artifact_types':[f['artifact_type'] for f in report['findings']]}
    results['model_unchanged']=ground['model_sha256']==digest(model)
    results['limitations']='Only these working directories are surveyed. Explicit log/cache options determine persistence. Cache token IDs are not decoded. File removal is on a copy, not raw filesystem recovery.'
    (case/'results.json').write_text(json.dumps(results,indent=2))
    print(json.dumps(results,indent=2))


if __name__=='__main__':main()
