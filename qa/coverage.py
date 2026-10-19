"""Map every visible menu action to fresh checks; never equate mocks with GUI use."""
import json,sys
from pathlib import Path

def coverage(out):
    unit=json.loads((out/'unit.json').read_text())
    checks=unit['tests'];packaged=json.loads((out/'packaged-menus.json').read_text())
    rows=[]
    def add(menu,option,test,kind='simulated_gui'):
        matched=[r for r in checks if r['id'].endswith('.'+test)]
        status='PASS' if matched and all(r['status']=='PASS' for r in matched) else 'FAIL' if matched else 'NOT TESTED'
        rows.append({'menu':menu,'option':option,'category':kind,'status':status,'test_ids':[r['id'] for r in matched]})
    for page,options in [('Home',('1 Scan this Mac','2 Analyze evidence','3 Open a case','4 Case tools','5 Diagnostics & validation','Q Quit')),('Case tools',('1 Verify case integrity','2 Compare two cases','3 Export reports','4 Package a case')),('Diagnostics',('1 Runtime diagnostics','2 Synthetic validation'))]:
        for option in options:
            rows.append({'menu':page,'option':option,'category':'interactive_pty','status':'PASS' if packaged['passed'] else 'FAIL','test_ids':['packaged_menus:folder_menu_workflows native and portable']})
    for option in ('B Back from submenu','C Cancel to home'):
        add('Navigation',option,'test_submenu_routes','unit')
    for option in ('Up','Down','Enter'):
        add('Navigation',option,'test_raw_arrow_wrap','unit')
    for option in ('1 Browse folder','2 Browse file'):
        add('Evidence',option,'test_source_browse_each_type')
    add('Evidence','3 Enter path (file/folder)','test_source_invalid_missing_retry')
    add('Case folder','2 Enter path','test_source_manual_folder_number_two')
    add('Evidence','B Back','test_manual_back_returns_picker')
    add('Evidence','C Cancel','test_cancel_each_shared_prompt')
    add('Native picker adapter','Cancel','test_source_picker_cancel')
    add('Native picker adapter','Failure and manual retry','test_source_picker_failure_manual_fallback')
    for option,test in [('1 Browse folder','test_browse_destination'),('2 Enter path','test_manual_destination_confirm'),('3 Suggested','test_suggested_destination'),('B Back','test_manual_output_back_returns_picker'),('C Cancel','test_cancel_each_shared_prompt')]:add('Output',option,test)
    for option,test in [('1 Standard / Enter','test_numbered_settings_choices'),('2 Advanced','test_numbered_settings_choices'),('B Back','test_advanced_back_to_standard'),('C Cancel','test_cancel_each_shared_prompt')]:add('Settings',option,test)
    for label in ('1 macOS','2 Windows','3 Linux','4 Unknown'):add('Evidence OS',label,'test_numbered_settings_choices')
    for label in ('B Back','C Cancel'):add('Evidence OS',label,'test_offline_os_back_and_cancel')
    for title in ('Historical residue','Include Trash'):
        for label in ('Y Confirm','N Decline'):add(title,label,'test_advanced_scan_yes_and_no')
    for label,test in [('Y Confirm','test_confirmation_requires_explicit_answer'),('N Decline','test_confirmation_requires_explicit_answer'),('B Back','test_back_preserves_prior_input'),('C Cancel','test_cancel_each_shared_prompt')]:add('Confirmation',label,test)
    for label,test in [('S Full Disk Access','test_settings_then_successful_recheck'),('R Recheck','test_settings_then_successful_recheck'),('L Continue with gaps','test_explicit_limited_choice'),('B Back','test_preflight_back'),('C Cancel','test_blocked_cannot_silently_continue')]:add('Access preflight',label,test)
    for label,test in [('B Main menu / Reports','test_result_details_report_and_back'),('F Open output folder','test_finder_explicit_action'),('O Open report','test_result_details_report_and_back'),('D Details','test_result_details_report_and_back'),('P Access settings','test_result_settings_confirm_decline_back_failure')]:add('Results',label,test)
    for label in ('Y Open settings','N Decline','B Back'):add('Settings confirmation',label,'test_result_settings_confirm_decline_back_failure')
    for label,test in [('E Export copies','test_reports_export_decline_runs_nothing'),('B Choose case','test_reports_back_selects_another_case'),('C Main menu','test_reports_open_each_file_and_invalid')]:add('Reports',label,test)
    # Export execution is additionally exercised by the complete PTY workflow.
    from llm_forensics.report_export import REPORT_NAMES
    for name in REPORT_NAMES:add('Reports','Number: '+name,'test_reports_open_each_file_and_invalid')
    rows.append({'menu':'Completion/failure','option':'Enter return','category':'interactive_pty','status':'PASS' if packaged['passed'] else 'FAIL','test_ids':['packaged_menus:folder_menu_workflows; separate failure_return checks']})
    return {'passed':all(r['status']=='PASS' for r in rows),'options':rows,'limitations':'PASS refers to the named automated action/adapter checks only. Native picker, actual GUI, real-runner and independent-Mac gates remain separate.'}
if __name__=='__main__':
    sys.path.insert(0,str(Path.cwd()));out=Path(sys.argv[1]);data=coverage(out)
    with (out/'menu-coverage.json').open('x') as f:json.dump(data,f,indent=2)
    print(json.dumps({'passed':data['passed'],'options':len(data['options'])}))
    raise SystemExit(0 if data['passed'] else 1)
