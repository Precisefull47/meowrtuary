"""unittest adapter retaining one machine-readable result per executed test."""
import argparse,json,time,unittest
from pathlib import Path
class Result(unittest.TextTestResult):
    def startTest(self,test):
        self.started=time.monotonic();super().startTest(test)
    def record(self,test,status,detail=''):
        self.rows.append({'id':test.id(),'status':status,'seconds':round(time.monotonic()-self.started,4),'detail':detail})
    def addSuccess(self,test):super().addSuccess(test);self.record(test,'PASS')
    def addFailure(self,test,err):super().addFailure(test,err);self.record(test,'FAIL',self._exc_info_to_string(err,test))
    def addError(self,test,err):super().addError(test,err);self.record(test,'FAIL',self._exc_info_to_string(err,test))
    def addSkip(self,test,reason):super().addSkip(test,reason);self.record(test,'NOT TESTED',reason)
    def addExpectedFailure(self,test,err):
        super().addExpectedFailure(test,err);self.record(test,'NOT TESTED','Expected failure is not a pass')
    def addUnexpectedSuccess(self,test):
        super().addUnexpectedSuccess(test);self.record(test,'FAIL','Unexpected success')
    def addSubTest(self,test,subtest,err):
        super().addSubTest(test,subtest,err)
        if err:self.record(subtest,'FAIL',self._exc_info_to_string(err,test))
    def __init__(self,*args,**kwargs):super().__init__(*args,**kwargs);self.rows=[]
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--suite',default='tests');p.add_argument('--output',required=True,type=Path);a=p.parse_args()
    import sys
    sys.path.insert(0,str(Path.cwd()))
    suite=unittest.defaultTestLoader.discover(a.suite)
    result=unittest.TextTestRunner(verbosity=2,resultclass=Result).run(suite)
    passed=result.wasSuccessful() and result.testsRun>0 and not result.skipped and len(result.rows)>=result.testsRun and all(r['status']=='PASS' for r in result.rows)
    with a.output.open('x') as f:json.dump({'passed':passed,'count':result.testsRun,'tests':result.rows},f,indent=2)
    raise SystemExit(0 if passed else 1)
