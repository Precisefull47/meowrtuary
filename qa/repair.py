"""Persistent, bounded repair ledger. The scheduled Codex agent supplies the fix."""
import argparse,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from qa.run import STATE,RUNS,locked,write_json,git
MAX_ATTEMPTS=3

def load_report(path):
    path=path.resolve(strict=True)
    if not path.is_relative_to(RUNS.resolve()):raise ValueError('Use a report produced by this QA installation')
    return json.loads(path.read_text())

def reserve(original,confirmation,key,reason):
    a=load_report(original);b=load_report(confirmation)
    if a['run_id']==b['run_id']:raise ValueError('A distinct confirmation run is required')
    if a['campaign']!=b['campaign'] or a['source_sha256']!=b['source_sha256']:raise ValueError('Reproduce on the same source before modifying it')
    for report in (a,b):
        row=next((r for r in report['checks'] if r['id']==key),None)
        if not row or row['status']!='FAIL':raise ValueError('Only reproduced executable failures are repairable')
    work=Path(a['workspace']).resolve(strict=True)
    if not work.is_relative_to((STATE/'worktrees').resolve()):raise ValueError('Not an isolated QA worktree')
    if not git(work,'branch','--show-current').startswith('qa/'):raise ValueError('Repairs must remain on QA branches')
    ledger=STATE/'repairs';ledger.mkdir(parents=True,exist_ok=True)
    incident=a['campaign']+'-'+key
    if any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in incident):raise ValueError('Invalid incident key')
    with locked(STATE/'repair.lock'):
        attempts=[p for p in ledger.glob(incident+'-attempt-*.json') if not p.name.endswith('.result.json')]
        if len(attempts)>=MAX_ATTEMPTS:raise ValueError('Repair budget exhausted: human intervention required')
        number=len(attempts)+1;target=ledger/f'{incident}-attempt-{number}.json'
        write_json(target,{'incident':incident,'attempt':number,'limit':MAX_ATTEMPTS,'run':a['run_id'],'check':key,'worktree':str(work),'reason':reason,'status':'RESERVED','confirmation_run':b['run_id']})
    return target

def complete(reservation,affected,full,note):
    reservation=reservation.resolve(strict=True)
    if reservation.parent!=(STATE/'repairs').resolve():raise ValueError('Not a repair reservation')
    event=json.loads(reservation.read_text());targeted=load_report(affected);regression=load_report(full)
    if targeted['campaign']!=regression['campaign'] or not event['incident'].startswith(regression['campaign']+'-'):raise ValueError('Mismatched repair campaign')
    if targeted['source_sha256']!=regression['source_sha256']:raise ValueError('Affected and full tests must use the same repaired source')
    row=next((r for r in targeted['checks'] if r['id']==event['check']),None)
    passed=bool(row and row['status']=='PASS' and regression['automated_passed'] and not regression['partial'])
    result={**event,'status':'FIX_VERIFIED' if passed else 'RETEST_FAILED','affected_report':str(affected),'full_report':str(full),'fix':note,'deployment_ready':regression['deployment_ready']}
    write_json(reservation.with_suffix('.result.json'),result)
    return result
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='action',required=True)
    r=sub.add_parser('reserve');r.add_argument('report',type=Path);r.add_argument('confirmation',type=Path);r.add_argument('check');r.add_argument('--reason',required=True)
    c=sub.add_parser('complete');c.add_argument('reservation',type=Path);c.add_argument('affected',type=Path);c.add_argument('full',type=Path);c.add_argument('--note',required=True)
    a=p.parse_args()
    if a.action=='reserve':print(reserve(a.report,a.confirmation,a.check,a.reason))
    else:print(json.dumps(complete(a.reservation,a.affected,a.full,a.note)))
