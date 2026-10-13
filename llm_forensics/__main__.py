from .output_location import create_output, check_storage
import argparse
import json
import sys
from pathlib import Path

from . import __version__


def input_path(value):
    if not value.strip() or '\x00' in value:
        raise argparse.ArgumentTypeError('Path must be nonempty and contain no NUL characters')
    return Path(value).expanduser()


def main():
    from .report import render_html
    from .scanner import scan
    from .discovery import SOURCE_OSES
    from .live import discover, scan_locations
    from .token_decode import decode_report
    from .timeline import build_timeline, write_timeline
    from .acquisition import acquire, verify_case
    from .terminal import banner, artifact_table, COMMAND_NAME, coverage_text
    from .assessment import enrich
    from .comparison import compare, render_comparison
    from .validation_kit import run_kit
    from .ground_truth import score
    from .structured import report_json
    from .case_package import seal_case, verify_package, bundle_case

    if '--no-animation' in sys.argv or '--reduced-motion' in sys.argv:
        import os
        os.environ['LLF_REDUCED_MOTION']='1'
        sys.argv[:]=[arg for arg in sys.argv if arg not in ('--no-animation','--reduced-motion')]
    if sys.argv[1:]==['--menu'] or (len(sys.argv)==1 and sys.stdin.isatty() and sys.stdout.isatty()):
        from .menu import menu
        menu()
        return
    parser = argparse.ArgumentParser(allow_abbrev=False, prog=COMMAND_NAME, description="Inspect existing local LLM artifacts in an explicit evidence folder.")
    parser.add_argument("--no-animation", "--reduced-motion", action="store_true", help="Disable startup animation and operation spinners")
    parser.add_argument("--doctor", action="store_true", help="Check Python, SQLite and archive runtime without reading evidence (use alone)")
    parser.add_argument("--menu", action="store_true", help="Open the guided terminal menu (use on its own)")
    parser.add_argument("evidence", type=input_path, nargs="?", help="Evidence file or folder (omit with --live)")
    parser.add_argument("--live", action="store_true", help="Automatically inspect known local LLM data locations")
    parser.add_argument("--all-users", action="store_true", help="With --live, discover other local user profiles within current permissions")
    parser.add_argument("--output", type=input_path, help="New report directory outside evidence folder")
    parser.add_argument("--max-file-mb", type=int, default=8)
    parser.add_argument("--source-os", choices=SOURCE_OSES, default="unknown", help="Original evidence OS, independent of the analysis computer")
    parser.add_argument("--format", choices=("json", "html", "both"), default="json", help="Export format (default: json; terminal summary always shown)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--export-conversations", action="store_true", help="Export recovered conversation records with source references")
    parser.add_argument("--recover-deleted", action="store_true", help="Attempt experimental Ollama SQLite freelist recovery; report historical candidates separately")
    parser.add_argument("--include-trash", action="store_true", help="With --live on macOS, also scan user Trash for supported artifacts")
    parser.add_argument("--decode-model", type=input_path, help="Decode supported session tokens with this GGUF vocabulary; model matching is operator-supplied")
    parser.add_argument("--timeline", action="store_true", help="Export UTC chronology and undated records as JSON/CSV and include an HTML timeline")
    parser.add_argument("--acquire", action="store_true", help="Preserve selected raw evidence and a manifest, then analyze the captured copies")
    parser.add_argument("--extra-path", type=input_path, action="append", default=[], help="Additional explicit evidence file/directory (repeatable)")
    parser.add_argument("--ollama-home", type=input_path, action="append", default=[], help="Custom Ollama home; requires --acquire (repeatable)")
    parser.add_argument("--lmstudio-home", type=input_path, action="append", default=[], help="Custom LM Studio home; requires --acquire (repeatable)")
    parser.add_argument("--verify-case", type=input_path, help="Check captured files against an existing case manifest; no scan performed")
    parser.add_argument("--strict", action="store_true", help="Return exit code 3 for incomplete scans/captures after writing reports")
    parser.add_argument('--seal-case', type=input_path, help='Create an unsigned integrity manifest for existing evidence and report files')
    parser.add_argument('--verify-package', type=input_path, help='Verify all files against a case integrity manifest')
    parser.add_argument('--bundle-case', type=input_path, help='Bundle a sealed case; requires new --output directory')
    # Keep --verify-case JSON and --version clean for scripts.
    if sys.stdout.isatty() and not any(arg.split('=', 1)[0] in ('--verify-case', '--verify-package', '--version') for arg in sys.argv[1:]):
        print(banner(), flush=True)
    parser.add_argument('--export-reports', type=input_path, help='Copy supported reports outside a case; requires new --output')
    parser.add_argument('--compare', nargs=2, type=input_path, metavar=('BEFORE', 'AFTER'), help='Compare two report.json files or case folders; requires --output')
    parser.add_argument('--score-records', nargs=2, type=input_path, metavar=('EXPECTED', 'REPORT'), help='Score independent expected role/text records against a report; requires --output')
    parser.add_argument('--self-test', action='store_true', help='Run isolated synthetic acceptance/recovery checks; requires a new --output directory')
    if len(sys.argv) == 1:
        parser.print_help()
        return
    args = parser.parse_args()
    supplied={arg.split('=',1)[0] for arg in sys.argv[1:] if arg.startswith('--')}
    operations={'--export-reports','--verify-case','--verify-package','--seal-case','--bundle-case','--compare','--score-records','--self-test','--doctor'}
    chosen=supplied & operations
    if len(chosen)>1:parser.error('Choose one operation at a time')
    if chosen:
        operation=next(iter(chosen))
        allowed={operation,'--output'} if operation in {'--export-reports','--bundle-case','--compare','--score-records','--self-test'} else {operation}
        if supplied-allowed or args.evidence:parser.error(operation+' cannot be combined with scan or unrelated options')

    if args.export_reports:
        if args.output is None:parser.error('--output is required')
        from .report_export import export_reports
        try:
            result=export_reports(args.export_reports,args.output)
            print(json.dumps(result,indent=2));return
        except (OSError,ValueError) as exc:parser.exit(1,'Report export failed: '+str(exc)+'\n')
    if args.menu:parser.error("--menu must be used on its own")
    if args.seal_case or args.verify_package or args.bundle_case:
        if sum(bool(v) for v in (args.seal_case,args.verify_package,args.bundle_case))!=1 or args.evidence or args.live or args.acquire or args.compare or args.self_test or args.score_records or args.verify_case or args.extra_path or args.ollama_home or args.lmstudio_home or args.decode_model or args.recover_deleted or args.timeline or args.export_conversations or args.all_users or args.include_trash:
            parser.error('Case packaging must be used separately from scan/validation options')
        if bool(args.output)!=bool(args.bundle_case):parser.error('--output is required only for --bundle-case')
        try:
            result=bundle_case(args.bundle_case,args.output) if args.bundle_case else seal_case(args.seal_case) if args.seal_case else verify_package(args.verify_package)
            print(json.dumps(result,indent=2,ensure_ascii=True))
            parser.exit(0 if result.get('verified',True) else 1)
        except (OSError,ValueError,TypeError,KeyError) as exc:parser.exit(1,f'Case operation failed: {exc}\n')
    if args.compare or args.self_test or args.score_records:
        if sum(bool(v) for v in (args.compare,args.self_test,args.score_records)) > 1 or args.evidence or args.live or args.acquire or args.verify_case or args.extra_path or args.ollama_home or args.lmstudio_home or args.decode_model or args.all_users or args.include_trash or args.recover_deleted or args.timeline or args.export_conversations:
            parser.error('Comparison/self-test must be used separately from scan options')
        if args.output is None: parser.error('--output is required')
        try:
            output=args.output.resolve()
            if args.self_test:
                result=run_kit(output)
                print(('PASS' if result['passed'] else 'FAIL') + ': synthetic validation; real runner validation remains separate.')
                print('Results: ' + ascii(str(output/'validation-results.json')))
                parser.exit(0 if result['passed'] else 1)
            for source in (args.compare or args.score_records):
                boundary=source.resolve()
                if output==boundary or boundary in output.parents: raise ValueError('Comparison output must be outside input cases')
            if args.score_records:
                result=score(*args.score_records)
                create_output(output)
                (output/'accuracy.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
                print(f"Exact record comparison: {result['matched_records']} matched, {result['missed_records']} missed, {result['unexpected_records']} unexpected")
                print('Results: '+ascii(str(output/'accuracy.json')))
                parser.exit(0 if result['exact_match'] else 3)
            result=compare(*args.compare)
            create_output(output)
            (output/'comparison.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
            (output/'comparison.html').write_text(render_comparison(result),encoding='utf-8')
            print('Case comparison: '+json.dumps(result['summary']))
            print('Not observed after does not mean deleted.')
            print('Exports: '+ascii(str(output)))
            return
        except (OSError,ValueError,TypeError,KeyError) as exc: parser.exit(1,f'Operation failed: {exc}\n')
    if args.verify_case:
        if args.evidence or args.live or args.output or args.acquire or args.extra_path or args.ollama_home or args.lmstudio_home:
            parser.error("--verify-case must be used without scan paths or --output")
        try:verification=verify_case(args.verify_case.absolute())
        except (OSError,ValueError,KeyError,TypeError) as exc:parser.exit(1,f"Verification failed: {exc}\n")
        print(json.dumps(verification,indent=2,ensure_ascii=True))
        parser.exit(0 if verification['verified'] else 1)
    if args.output is None:parser.error("--output is required for a scan")
    if (args.ollama_home or args.lmstudio_home) and not args.acquire:
        parser.error("Custom runner homes require --acquire to preserve their declared path mapping")
    custom_only=bool(args.extra_path or args.ollama_home or args.lmstudio_home) and not args.live and not args.evidence
    if not custom_only and args.live == bool(args.evidence):
        parser.error("Choose either an evidence path or --live")
    if args.include_trash and not args.live:
        parser.error("--include-trash requires --live; offline scans already inspect Trash folders in supplied evidence")
    if args.all_users and not args.live:
        parser.error("--all-users requires --live")
    if args.live and args.source_os != "unknown":
        parser.error("Live mode uses the actual host OS; omit --source-os")
    root = args.evidence.absolute() if args.evidence else None
    output = args.output.resolve()
    if root is not None and (output == root.resolve() or root.resolve() in output.parents):
        parser.error("Output must be outside the evidence folder.")
    if output.exists():
        parser.error("Output directory already exists; choose a new directory to avoid overwriting reports.")
    if not 1 <= args.max_file_mb <= 128:
        parser.error("--max-file-mb must be between 1 and 128")
    try:
        if args.live:
            system, locations, issues = discover(args.all_users, include_trash=args.include_trash)
        else:
            system, locations, issues = args.source_os, ([root] if root else []), []
        scopes=[(p,'.ollama') for p in args.ollama_home]+[(p,'.lmstudio') for p in args.lmstudio_home]
        scopes += [(p,None) for p in locations+args.extra_path]
        for source,_ in scopes:
            resolved=source.resolve()
            if output==resolved or resolved in output.parents:parser.error("Output must be outside every source scope")
        if args.acquire:
            manifest=acquire(scopes,output,system,args.max_file_mb*1024*1024,optional_sources=locations if args.live else ())
            report=scan(output/'evidence',args.max_file_mb*1024*1024,source_os=system,recover_deleted=args.recover_deleted)
            report['acquisition']={k:v for k,v in manifest.items() if k!='files'}
            report['issues'].extend(issues+manifest['issues'])
            report['acquisition_manifest']='acquisition-manifest.json'
            captured={str((output/e['case_path']).absolute()):e for e in manifest['files'] if e['status']=='captured'}
            for finding in report['findings']:
                entry=captured.get(finding['source_path'])
                if entry:
                    finding['original_source_path']=entry['source_path']
                    finding['acquisition_case_path']=entry['case_path']
                    finding['acquisition_integrity']='captured SHA-256 recorded in manifest'
                    finding['original_source_size_bytes']=entry['source_size_bytes']
                    finding['capture_mode']=entry['capture_mode']
                    if entry['capture_mode']=='prefix':finding['limitations'].append('Acquisition preserved only the model header, not the complete model file.')
            report['limitations'].extend(manifest['limitations'])
        elif args.live or args.extra_path or custom_only:
            report=scan_locations([p for p,_ in scopes],system,output,args.max_file_mb*1024*1024,issues,recover_deleted=args.recover_deleted,optional_sources=locations if args.live else ())
            if not args.live:
                report['evidence_root']='Explicit multi-path scan'
                report['source_os_basis']='operator declaration'
        else:
            report=scan(root,args.max_file_mb*1024*1024,source_os=system,recover_deleted=args.recover_deleted)
        if args.decode_model:
            decode_report(report, args.decode_model)
        report['analysis_options']={'recover_deleted':args.recover_deleted,'decode_requested':bool(args.decode_model),
            'max_file_bytes':args.max_file_mb*1024*1024,'source_os':system}
        report['run_scope']={'live':args.live,'all_users':args.all_users,'include_trash':args.include_trash,
            'acquire':args.acquire,'sources':[{'path':str(p.absolute()),'alias':alias} for p,alias in scopes]}
        enrich(report)
        if args.timeline:
            report["timeline"] = build_timeline(report)
        if not args.acquire:
            create_output(output)
        check_storage()
        if args.timeline:
            write_timeline(report["timeline"], output)
        if args.decode_model:
            decoded=[]
            for finding in report["findings"]:
                if finding["artifact_type"]!="llama_session":continue
                for record in finding["observations"]:
                    decoded.append({**record,"source_path":finding["source_path"],"original_source_path":finding.get("original_source_path"),"source_sha256":finding.get("sha256"),"artifact_id":finding["id"]})
            (output/"decoded-sessions.json").write_text(json.dumps({"records":decoded,"decoding_model":report["decoding_model"],"limitations":"Conditional vocabulary-based text reconstruction; no authenticated model association, message roles or complete-conversation claim."},indent=2,ensure_ascii=True),encoding="utf-8")
        if args.recover_deleted:
            recovery_records=[]
            recovery_sources=[]
            for finding in report['findings']:
                if 'recovery' not in finding: continue
                recovery_sources.append({'source_path':finding['source_path'],**{k:v for k,v in finding['recovery'].items() if k!='records'}})
                for record in finding['recovery']['records']:
                    recovery_records.append({**record,'artifact_id':finding['id'],'source_path':finding['source_path'],'original_source_path':finding.get('original_source_path'),'source_sha256':finding.get('sha256')})
            (output/'recovered-residue.json').write_text(json.dumps({'records':recovery_records,'sources':recovery_sources,'limitations':'Historical candidates are not confirmed deleted conversations; may include superseded or current records.'},indent=2,ensure_ascii=True),encoding='utf-8')
        if args.export_conversations:
            records = []
            for finding in report["findings"]:
                if finding["artifact_type"] not in {"saved_messages", "conversation_json", "cli_history", "desktop_sqlite"}:
                    continue
                for observation in finding["observations"]:
                    records.append({**observation, "artifact_id": finding["id"], "artifact_type": finding["artifact_type"], "source_path": finding["source_path"], "original_source_path": finding.get("original_source_path"), "source_sha256": finding.get("sha256"), "source_status": finding["status"], "linked_from": finding.get("linked_from", []), "acquisition_files": finding.get("acquisition_files", [])})
            (output / "conversations.json").write_text(json.dumps({"records": records, "limitations": "Record order is artifact order, not a cross-file timeline. CLI history includes commands as well as inputs. No actor attribution."}, indent=2, ensure_ascii=True), encoding="utf-8")
        if args.format in {"json", "both"}:
            (output / "report.json").write_text(report_json(report), encoding="utf-8")
        if args.format in {"html", "both"}:
            (output / "report.html").write_text(render_html(report), encoding="utf-8")
        seal_case(output)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Scan failed: {exc}\n")
    print(f"Local LLM Forensics {__version__} | Evidence OS: {report['source_os']}")
    print(coverage_text(report["coverage_summary"]))
    from .permission_help import has_access_denial, instructions
    if has_access_denial(report):print("\n"+instructions()+"\n")
    print(f"{len(report['findings'])} candidate artifacts | {len(report['issues'])} scan issues")
    print()
    print(artifact_table(report['findings'], live=args.live))
    if args.recover_deleted:
        print(f"Historical residue: {len(recovery_records)} distinct candidates; see recovered-residue.json for recovery coverage and limitations.")
    if args.timeline:
        summary=report["timeline"]["summary"]
        print(f"Timeline: {summary['dated_events']} dated events; {summary['undated_records']} records with unknown time.")
    print(f"Exports: {ascii(str(output))}")
    print("Experimental detection; no findings does not prove absence of LLM use.")
    incomplete=report['coverage_summary']['status'] != 'complete_within_scope'
    if args.strict and incomplete:parser.exit(3)


def entry_point():
    try:
        if '--doctor' in sys.argv[1:]:
            if sys.argv[1:]!=['--doctor']:
                print('--doctor must be used alone',file=sys.stderr);raise SystemExit(2)
            from .diagnostics import diagnose
            result=diagnose();print(json.dumps(result,indent=2));raise SystemExit(0 if result['passed'] else 1)
        main()
    except ImportError as exc:
        print('Required Python runtime component unavailable: '+str(exc)+'. Use the complete native bundle or a full Python 3.10+ installation; try --doctor.',file=sys.stderr)
        raise SystemExit(1)
    except (OSError,ValueError,OverflowError) as exc:
        print('Operation failed: '+ascii(str(exc))+'. Retain any partial case; it is not a completed acquisition.',file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        print('Interrupted. Retain the case and inspect its manifest; unfinished outputs are not a completed acquisition.',file=sys.stderr)
        raise SystemExit(130)


if __name__ == "__main__":
    entry_point()
