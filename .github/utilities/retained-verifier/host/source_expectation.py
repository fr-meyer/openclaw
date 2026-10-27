"""Independent source-derived expected CI bindings; no native issuer or I/O."""
import hashlib
import json


class Refusal(ValueError):pass


def require(ok,why):
    if not ok:raise Refusal(why)


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()


def derive(manifest,runtime,build,bound,session,profile_module):
    require(type(manifest)is dict and manifest.get('schema')=='ocv-public-source-v1','expect.source_manifest')
    source={row['path']:row for row in manifest['files']}
    require(len(source)==len(manifest['files']),'expect.source_duplicate')
    require(build['sourceManifestSha256']==bound['sourceManifestSha256'] and build['runIdentity']==bound['runIdentity'],
            'expect.build_binding')
    files=[]
    for row in runtime['files']:
        require(set(row)=={'path','sourcePath','bytes','sha256','mode'},'expect.runtime_row')
        files.append({'path':row['path'],'seedPath':'/seed/'+row['path'],
                      'bytes':row['bytes'],'sha256':row['sha256'],'mode':row['mode']})
    helper=runtime['helper']
    require(helper['sha256']==build['helperSha256'],'expect.helper')
    files.append({'path':'code/static-entry','seedPath':'/seed/code/static-entry','bytes':helper['bytes'],
                  'sha256':helper['sha256'],'mode':0o555})
    names={'ci_protocol.py':'native/ci_protocol.py','ci_profile.py':'native/ci_profile.py',
           'ci_fixture.py':'native/ci_fixture.py','ci_worker_core.py':'native/ci_worker.py',
           'worker.py':'bootstrap/worker_entry.py'}
    for name in ('native_cases.py','hosted_export.py','hosted_privacy.py','public-member-comparisons-v105-workboard.json'):
        names[name]='consumer/'+name
    for name,relative in names.items():
        row=source[relative];files.append({'path':'code/'+name,'seedPath':'/seed/code/'+name,
          'bytes':row['bytes'],'sha256':row['sha256'],'mode':0o444})
    require(len({row['path']for row in files})==len(files),'expect.runtime_duplicate')
    files.sort(key=lambda row:row['path'])
    consumers=('ci_fixture.py','native_cases.py','hosted_export.py','hosted_privacy.py','public-member-comparisons-v105-workboard.json')
    code={'entrySha256':build['helperSha256'],'workerSha256':source['bootstrap/worker_entry.py']['sha256'],
          'runtimeManifestSha256':sha(canonical(files)),
          'consumerCode':{name:{'bytes':source[names[name]]['bytes'],'sha256':source[names[name]]['sha256']}for name in consumers}}
    profile=source['native/CI-PROFILE.json']['sha256']
    require(profile==profile_module.DESIGN_PROFILE_SHA,'expect.profile')
    # The source-pinned profile module validates the supplied actual profile
    # separately in the I/O wrapper. This function never reads caller paths.
    return {'sessionId':session,'sourceManifestSha256':bound['sourceManifestSha256'],
      'buildControlSha256':bound['buildControlSha256'],'runIdentity':bound['runIdentity'],'code':code,
      'profileSha256':profile,'consumerSourceHashes':{name:source['consumer/'+name]['sha256']for name in
       ('hosted_export.py','hosted_privacy.py','public-member-comparisons-v105-workboard.json')}}


def expected(source,out,bound,session):
    # Called only after host source and output hashes are checked; all reads
    # are public artifacts. No validation or native capability is issued here.
    import ci_profile
    from ci_host import decode,read_regular
    manifest_raw=read_regular(source/'PUBLIC-SOURCE-MANIFEST.json',1048576)
    require(sha(manifest_raw)==bound['sourceManifestSha256'],'expect.source_control')
    manifest=decode(manifest_raw)
    runtime_raw=read_regular(out/'runtime.json',4*1024**2);runtime=decode(runtime_raw,4*1024**2)
    build_raw=read_regular(out/'build.json',32768)
    require(sha(build_raw)==bound['buildControlSha256'],'expect.build_control')
    build=decode(build_raw)
    require(sha(runtime_raw)==build['runtimeManifestSha256'],'expect.runtime_control')
    profile_raw=read_regular(source/'native/CI-PROFILE.json',16384)
    result=derive(manifest,runtime,build,bound,session,ci_profile)
    result['propertiesSha256']=sha(canonical(ci_profile.properties(profile_raw,session,'/var/lib/ci-verifier/'+session)))
    return result


if __name__=='__main__':raise SystemExit('inert_public_data_derivation_only')
