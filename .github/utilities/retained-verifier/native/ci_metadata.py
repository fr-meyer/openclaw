"""Fixed native-process metadata classification seam; no authentication grant.

Host signed Ubuntu APT and exact mkosi/Debian install admission must occur
before compiler/guest start in the outer job. This guest-side classifier does
not replace those package-manager checks or issue a security-base claim.
"""
import ci_archive_policy as policy
from ci_protocol import closed,require,sha
METADATA_CONTEXT_MANIFEST_SHA256=None


class Admission:
    def __init__(self,ops,paths,keyring_sha256,clock):
        closed(paths,{'release','packages','keyring'},'ci.metadata_paths')
        require(all(type(p) is str and p.startswith('/var/lib/apt/lists/') and '..' not in p.split('/')
            for k,p in paths.items() if k!='keyring') and paths['keyring']=='/usr/share/keyrings/debian-archive-keyring.gpg',
            'ci.actual_apt_context')
        require(type(keyring_sha256) is str and len(keyring_sha256)==64,'ci.keyring_pin_unbound')
        self.ops,self.paths,self.keyring_sha,self.clock=ops,paths,keyring_sha256,clock
        self.used=False;self.evidence=None
    def run(self):
        return self._run_literal_policy(policy.BOOKWORM)
    def _run_literal_policy(self,fixture):
        # Internal source-faithful fixture seam for local tests only. The native
        # entry calls run(), whose policy is the literal source BOOKWORM object.
        require(not self.used,'ci.metadata_once');self.used=True
        key=self.ops.read(self.paths['keyring'],1048576)
        require(sha(key)==self.keyring_sha,'ci.keyring_changed')
        release=self.ops.read(self.paths['release'],fixture.release_bytes+1)
        packages=self.ops.read(self.paths['packages'],fixture.packages_bytes+1)
        argv=('/usr/bin/gpgv','--status-fd=1','--keyring',self.paths['keyring'],self.paths['release'])
        from ci_native_port import command_boundary_refusal,command_capture_ok
        try:outcome=self.ops.command(argv,10)
        except BaseException as error:outcome=command_boundary_refusal(error)
        self.evidence={'argv':list(argv),'outcome':outcome}
        require(command_capture_ok(outcome),'ci.gpgv_capture_refused')
        require(outcome.get('stdoutFacts',{}).get('truncated') is False and
          outcome.get('stderrFacts',{}).get('truncated') is False,'ci.gpgv_capture_truncated')
        result=policy.classify(release,packages,returncode=outcome['exitCode'],timed_out=outcome['timedOut'],
          status=outcome['stdout'],checked_at=self.clock.utc(),fixture=fixture)
        return {'status':'classified','fixtureOnly':True,'nativeAuthenticationIssued':False,
          'classificationSha256':sha(__import__('ci_protocol').canonical(result))}
