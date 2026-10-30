"""Exact-source, secretless Linux proof. No subprocess or device-data reads."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import sys
import time
import unittest

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent.parent
WORKFLOW='.github/workflows/qualification-sysfs-proof.yml'
PREFIX='tools/qualification-sysfs-proof/'
SOURCE_FILES={PREFIX+'sysfs_block_attribute.py',PREFIX+'test_sysfs_block_attribute.py',
              PREFIX+'linux_proof.py'}
sha=lambda raw:hashlib.sha256(raw).hexdigest()
canonical=lambda value:json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')

def need(value,code):
    if not value:raise RuntimeError(code)

def source_file(path,cap):
    need(path.resolve()==path and path.is_file()and not path.is_symlink(),'source_shape')
    value=path.lstat();need(stat.S_ISREG(value.st_mode)and value.st_nlink==1 and 0<value.st_size<=cap,'source_metadata')
    raw=path.read_bytes();need(len(raw)==value.st_size,'source_changed');return raw

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def validate_sources():
    for key,size in(('GITHUB_SHA',40),('OCV_SOURCE_TREE',40),('OCV_SOURCE_MANIFEST_SHA',64)):
        need(re.fullmatch('[a-f0-9]{'+str(size)+'}',os.environ.get(key,''))is not None,'push_shape')
    need(os.environ.get('GITHUB_REPOSITORY')=='fr-meyer/openclaw'and
         os.environ.get('GITHUB_REF')=='refs/heads/retained-verifier-prerequisites'and
         os.environ.get('GITHUB_EVENT_NAME')=='push'and
         os.environ.get('GITHUB_RUN_ATTEMPT')=='1','push_identity')
    raw=source_file(HERE/'SOURCE-MANIFEST.json',16384)
    need(sha(raw)==os.environ['OCV_SOURCE_MANIFEST_SHA'],'manifest_hash')
    manifest=json.loads(raw)
    need(set(manifest)=={'schema','files'}and manifest['schema']=='qualification.sysfs-block-attribute-source.v1'and type(manifest['files'])is list,'manifest_shape')
    selected=set()
    for row in manifest['files']:
        need(type(row)is dict and set(row)=={'path','bytes','sha256'}and row['path']in SOURCE_FILES and row['path']not in selected,'manifest_row')
        need(str(PurePosixPath(row['path']))==row['path']and type(row['bytes'])is int and 0<row['bytes']<=65536,'manifest_path')
        value=source_file(ROOT/row['path'],65536)
        need(len(value)==row['bytes']and sha(value)==row['sha256'],'source_hash');selected.add(row['path'])
    need(selected==SOURCE_FILES and set(q.name for q in HERE.iterdir())==
         {'sysfs_block_attribute.py','test_sysfs_block_attribute.py','linux_proof.py','SOURCE-MANIFEST.json'},'source_roster')
    # The reviewed publisher pins the complete commit/tree and all five files
    # before the single ref update. Export the actual workflow hash for that
    # independent join; including it in this manifest would create a hash cycle.
    workflow_sha=sha(source_file(ROOT/WORKFLOW,65536))
    return sha(raw),workflow_sha


def synthetic():
    fixture=load('generic_sysfs_contract_tests',HERE/'test_sysfs_block_attribute.py')
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(fixture.Tests)
    result=unittest.TextTestRunner(stream=io.StringIO(),verbosity=0).run(suite)
    need(result.wasSuccessful()and result.testsRun==9,'synthetic_contract_failed')
    return result.testsRun

def real_linux():
    need(sys.platform=='linux','linux_required')
    reader=load('exact_generic_sysfs',HERE/'sysfs_block_attribute.py')
    entries=list(Path('/sys/dev/block').iterdir())
    need(0<len(entries)<=512,'native_block_inventory')
    numbers=sorted(entry.name for entry in entries if reader._major_minor(entry.name))
    chosen={}
    for number in numbers:
        node=(Path('/sys/dev/block')/number).resolve(strict=True)
        need(str(node).startswith('/sys/devices/'),'native_canonical_graph')
        kind='partition'if(node/'partition').exists()else'whole'
        chosen.setdefault(kind,(number,node))
        if len(chosen)==2:break
    need(bool(chosen),'native_attribute_witness_missing')
    counts={'directDevWitnesses':0,'directPartitionWitnesses':0,'ancestryCalls':0,
            'nominal4096Witnesses':0,'originalMetadataCapRefusals':0}
    observer=reader.BlockAttributeReader()
    for kind,(number,node)in sorted(chosen.items()):
        raw=reader._sysfs_block_attribute(str(node/'dev'))
        need(raw.strip().decode('ascii')==number,'native_dev_join')
        counts['directDevWitnesses']+=1
        nominal=(node/'dev').lstat().st_size
        counts['nominal4096Witnesses']+=int(nominal==4096)
        if nominal>128:
            try:reader._regular(str(node/'dev'),128,proc=True)
            except reader.Refusal as error:
                need(error.code=='observer.regular_identity','native_old_failure_kind')
                counts['originalMetadataCapRefusals']+=1
            else:raise RuntimeError('native_old_failure_not_reproduced')
        if kind=='partition':
            part=reader._sysfs_block_attribute(str(node/'partition')).strip().decode('ascii')
            need(re.fullmatch('[1-9][0-9]{0,9}',part)is not None and int(part)<2**31,'native_partition_value')
            counts['directPartitionWitnesses']+=1
        for _ in range(2):
            value=observer._block_ancestry(number)
            need(value['majorMinor']==number and value['isPartition']==(kind=='partition')and reader._major_minor(value['wholeMajorMinor']),'native_ancestry_join')
            counts['ancestryCalls']+=1
    need(counts['directDevWitnesses']>0 and counts['nominal4096Witnesses']>0 and counts['originalMetadataCapRefusals']>0,'native_attribute_witness_missing')
    counts['nativePartitionObserved']=counts['directPartitionWitnesses']>0
    counts['partitionAncestrySyntheticCoverage']=True
    counts['rawAttributeValuesOrPathsExported']=False
    return counts

def main():
    began=time.monotonic();result={'schema':'qualification.sysfs-block-attribute-proof.v1','status':'HOLD'}
    try:
        need(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'isolated_python_required')
        manifest_sha,workflow_sha=validate_sources();methods=synthetic();counts=real_linux()
        result.update(status='PASS_REAL_SYSFS_READER_AND_SYNTHETIC_CONTRACTS',
            sourceCommit=os.environ['GITHUB_SHA'],sourceTree=os.environ['OCV_SOURCE_TREE'],
            sourceManifestSha256=manifest_sha,workflowSha256=workflow_sha,
            syntheticMethods=methods,native=counts,pythonVersion=list(sys.version_info[:3]),
            realPrivateConfigurationDeviceIdentityOrOperationalAdmissionEstablished=False)
    except BaseException as error:
        result.update(failureClass=type(error).__name__,failureCode='bounded_sysfs_proof_failed')
    result['elapsedMilliseconds']=int((time.monotonic()-began)*1000)
    raw=canonical(result);need(len(raw)<=4096,'public_result_cap')
    output=Path(os.environ['RUNNER_TEMP'])/'sysfs-block-attribute-proof.json'
    fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:need(os.write(fd,raw)==len(raw),'public_result_short_write');os.fsync(fd)
    finally:os.close(fd)
    print(raw.decode('ascii'));return 0 if result['status'].startswith('PASS_')else 1

if __name__=='__main__':raise SystemExit(main())
