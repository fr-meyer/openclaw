import argparse,hashlib,json,os,pathlib,re,subprocess,sys
VERSION='5.0.1'
PATCH='90ba2969491e095cc2e92a4d38256dfcf64f85078ec29e1762b9429a00b35901'
SOURCE='d4cb7f20d2eb1079bc5775543990f2a5b527662e'
TREE='90fc8a5f3270e833120830ea3ac7e0b685113570'
MESSAGE='expected any number of assertion, but got none'
def validate_report(report,code,positive,filename):
 if type(code)!=int or (code!=0 if positive else code<=0): raise ValueError('wrong probe exit')
 if report.get('success') is not positive: raise ValueError('wrong report success')
 for key,value in {'numTotalTests':1,'numPassedTests':int(positive),'numFailedTests':int(not positive)}.items():
  if type(report.get(key))!=int or report[key]!=value: raise ValueError('wrong exact test count')
 for key in ['numPendingTests','numTodoTests','numRuntimeErrorTestSuites']:
  if report.get(key,0)!=0: raise ValueError('skip/todo/runtime error')
 if report.get('unhandledErrors',[]): raise ValueError('unhandled errors')
 suites=report.get('testResults')
 if not isinstance(suites,list) or len(suites)!=1: raise ValueError('wrong probe file count')
 suite=suites[0]
 if pathlib.Path(suite.get('name','')).resolve()!=pathlib.Path(filename).resolve() or suite.get('testExecError'): raise ValueError('wrong file/setup failure')
 cases=suite.get('assertionResults')
 if not isinstance(cases,list) or len(cases)!=1: raise ValueError('case never actually executed')
 case=cases[0]; expected_title='b-expect-real-assertion' if positive else 'b-expect-empty-body'
 if case.get('title')!=expected_title or case.get('status')!=('passed' if positive else 'failed'): raise ValueError('wrong actual case')
 failures=case.get('failureMessages',[])
 if positive:
  if failures: raise ValueError('asserted case errors')
 elif not isinstance(failures,list) or len(failures)!=1 or not isinstance(failures[0],str) or MESSAGE not in failures[0]: raise ValueError('not actual zero-expect refusal')
 return {'file':str(pathlib.Path(filename).resolve()),'testCase':expected_title,'exitCode':code,'outcome':'passed' if positive else 'zero-expect-refused'}
def main():
 parser=argparse.ArgumentParser(); parser.add_argument('--image-id',required=True); args=parser.parse_args()
 if not re.fullmatch('sha256:[0-9a-f]{64}',args.image_id): raise ValueError('unbound image')
 support=pathlib.Path(__file__).resolve().parent
 raw=(support/'b-full-source.json').read_bytes(); digest=hashlib.sha256(raw).hexdigest()
 if digest!=(support/'b-full-source.sha256').read_text().strip(): raise ValueError('manifest digest')
 manifest=json.loads(raw)
 if manifest['source']!=SOURCE or manifest['tree']!=TREE or not re.fullmatch('[0-9a-f]{40}',manifest['workflow']) or manifest['workflow']==SOURCE: raise ValueError('unbound S/W')
 if json.loads(pathlib.Path('/app/node_modules/vitest/package.json').read_text())['version']!=VERSION: raise ValueError('wrong installed Vitest')
 if hashlib.sha256(pathlib.Path('patches/vitest@5.0.1.patch').read_bytes()).hexdigest()!=PATCH: raise ValueError('wrong source patch')
 version=subprocess.run(['pnpm','exec','vitest','--version'],capture_output=True,text=True,check=True,timeout=30).stdout.strip()
 if not re.search(r'vitest/5\.0\.1(?:\s|$)',version): raise ValueError('wrong executable version')
 out=pathlib.Path('/tmp/b-expect-probe'); out.mkdir(exist_ok=False)
 results=[]
 for label,positive in [('empty',False),('asserted',True)]:
  fixture=support/('b-expect-'+label+'.test.mjs'); report=out/(label+'.json')
  command=['pnpm','exec','vitest','run',str(fixture),'--config',str(support/'b-expect-probe.config.mjs'),'--expect.requireAssertions','--maxWorkers=1','--fileParallelism=false','--retry=0','--reporter=json','--outputFile',str(report)]
  result=subprocess.run(command,capture_output=True,text=True,timeout=90)
  (out/(label+'.stdout')).write_text(result.stdout); (out/(label+'.stderr')).write_text(result.stderr)
  if not report.is_file(): raise ValueError('no actual probe report')
  item=validate_report(json.loads(report.read_text()),result.returncode,positive,fixture); item['args']=command; item['reportSha256']=hashlib.sha256(report.read_bytes()).hexdigest(); results.append(item)
 receipt={'status':'ACTUAL_OFFLINE_PROBE_PASS','source':SOURCE,'tree':TREE,'workflow':manifest['workflow'],'manifestSha256':digest,'imageId':args.image_id,'vitestVersion':VERSION,'vitestPatchSha256':PATCH,'versionOutput':version,'probes':results,'separateFromFourCandidateInventory':True}
 target=out/'receipt.json'; temp=out/'receipt.tmp'; temp.write_text(json.dumps(receipt,sort_keys=True)); os.replace(temp,target)
 print('B_EXPECT_ENFORCEMENT_RECEIPT='+target.read_text(),flush=True)
if __name__=='__main__': main()
