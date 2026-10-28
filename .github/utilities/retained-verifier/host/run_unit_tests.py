"""Run only source-manifest-listed generic unit tests in an isolated child."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path,PurePosixPath
import re
import sys
import time
import unittest

SUITE_PREFIX={'archive':'apt','apt':'apt','outer':'outer','native':'native','runtime':'runtime',
              'build':'build','bootstrap':'bootstrap','host':'host','consumer':'consumer','integrated':'integrated'}


def selected_paths(rows,suite):
    if suite not in SUITE_PREFIX:raise ValueError('test_suite')
    prefix=SUITE_PREFIX[suite]+'/'
    result=[]
    for name in sorted(rows):
        p=PurePosixPath(name)
        if name.startswith(prefix) and len(p.parts)==2 and re.fullmatch(r'test_[a-z0-9_]+\.py',p.name):
            if suite=='archive' and p.name!='test_archive_policy.py':continue
            if suite=='apt' and p.name=='test_archive_policy.py':continue
            result.append(name)
    if not result:raise ValueError('test_suite_empty')
    return result


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--suite',required=True,choices=tuple(SUITE_PREFIX));args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    manifest=json.loads((root/'PUBLIC-SOURCE-MANIFEST.json').read_bytes())
    if manifest.get('schema')!='ocv-public-source-v1':raise ValueError('test_manifest')
    rows={row['path']:row for row in manifest['files']}
    paths=selected_paths(rows,args.suite)
    # Every inserted path is the separately checked immutable public source
    # tuple. No site/user/current-working-directory import path is added.
    for leaf in ('host','native','apt','outer','runtime','build','consumer','bootstrap','integrated'):
        sys.path.insert(0,str(root/leaf))
    sys.path.insert(0,str(root/SUITE_PREFIX[args.suite]))
    suite=unittest.TestSuite();started=time.monotonic()
    for name in paths:
        data=(root/name).read_bytes();row=rows[name]
        if len(data)!=row['bytes'] or hashlib.sha256(data).hexdigest()!=row['sha256']:raise ValueError('test_source_changed')
        module_name='ocv_test_'+args.suite+'_'+Path(name).stem
        spec=importlib.util.spec_from_file_location(module_name,root/name)
        module=importlib.util.module_from_spec(spec);sys.modules[module_name]=module;spec.loader.exec_module(module)
        suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(module))
    result=unittest.TextTestRunner(stream=sys.stderr,verbosity=2).run(suite)
    value={'schema':'ocv-source-tests-v1','suite':args.suite,'testsRun':result.testsRun,
           'successful':result.wasSuccessful(),'elapsedMilliseconds':int((time.monotonic()-started)*1000),
           'nativeProof':False}
    sys.stdout.write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
    return 0 if result.wasSuccessful() else 1


if __name__=='__main__':raise SystemExit(main())
