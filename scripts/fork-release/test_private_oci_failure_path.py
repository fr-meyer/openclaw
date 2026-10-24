"""Release-only failure-path integration; no build, network or real attestation.

Actual workflow/composite Bash and the privacy, opaque archive and transfer CLI
owners run against a synthetic OCI. Only the external attestor identity and
provider transport are test fixtures. Their proofs do not qualify GitHub OIDC,
GCS enforcement, native image execution or production deployment.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
from types import SimpleNamespace as NS
import unittest

import private_oci_bundle as packer
import private_oci_transfer as transfer
from test_hosted_build_workflow import expression, step
from test_private_oci_bundle import Fixture, WORKFLOW, BUILT

REPO = Path(__file__).resolve().parents[2]
OWNER = Path(__file__).resolve().parent
ACTION = REPO / ".github/actions/retain-private-oci/action.yml"
WORKFLOW_FILE = REPO / ".github/workflows/fork-release-pipeline.yml"
NOW = 1792843200.0


def body(section):
    return textwrap.dedent(section.split("run: |\n", 1)[1])


def action_step(name):
    return ACTION.read_text().split("    - name: " + name + "\n", 1)[1].split("    - name:", 1)[0]


def condition(section):
    lines = section.splitlines()
    for index, line in enumerate(lines):
        if line.lstrip().startswith("if:"):
            indent = len(line) - len(line.lstrip())
            value = line.strip()[3:].strip()
            if value == ">-":
                continuation = []
                for item in lines[index + 1:]:
                    if item.strip() and len(item) - len(item.lstrip()) <= indent:
                        break
                    continuation.append(item.strip())
                value = " ".join(continuation)
            return value
    return "${{ success() }}"


def selected(section, steps, *, successful, cancelled=False):
    value = condition(section).replace("!cancelled()", "not cancelled()")
    # GitHub inserts success() only when an explicit status function is absent.
    # Embedded composite steps use their own action status, not a failed outer
    # privacy step; the actual caller's always() admits this failure path.
    if not any(name + "(" in value for name in ("always", "success", "failure", "cancelled")):
        value = "${{ success() && (" + value.strip().removeprefix("${{").removesuffix("}}").strip() + ") }}"
    return expression(value, steps=steps, github=NS(event_name="push"),
        inputs=NS(export_public_artifact=False, artifact_storage_approved=False),
        always=lambda: True, success=lambda: successful, failure=lambda: not successful,
        cancelled=lambda: cancelled)


KEYGEN = """
const fs=require('node:fs'), crypto=require('node:crypto');
const [priv,pub]=process.argv.slice(1), keys=crypto.generateKeyPairSync('ed25519');
fs.writeFileSync(priv,keys.privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600,flag:'wx'});
fs.writeFileSync(pub,keys.publicKey.export({type:'spki',format:'pem'}),{mode:0o600,flag:'wx'});
"""
SIGN = """
const fs=require('node:fs'), crypto=require('node:crypto');
const [archive,expected,name,origin,privateKey,output]=process.argv.slice(1);
const bytes=fs.readFileSync(archive), digest=crypto.createHash('sha256').update(bytes).digest('hex');
if(expected!=='sha256:'+digest || name!=='retained-oci.tar')process.exit(2);
const original=fs.readFileSync(origin), custody=JSON.parse(original);
const statement={schema:'fixture.unqualified-oci-attestation.v1',fixtureOnly:true,githubOIDC:false,
  subject:[{name,digest:{sha256:digest}}],archiveBytes:bytes.length,producer:custody.producer,
  sourceSha:custody.sourceSha,sourceTree:custody.sourceTree,
  custodySha256:crypto.createHash('sha256').update(original).digest('hex'),
  imageQualified:false,productionAuthorized:false};
const payload=Buffer.from(JSON.stringify(statement));
fs.writeFileSync(output,JSON.stringify({statement:payload.toString('base64'),
  signature:crypto.sign(null,payload,fs.readFileSync(privateKey)).toString('base64')}),{mode:0o600,flag:'wx'});
"""
VERIFY = """
const fs=require('node:fs'), crypto=require('node:crypto');
const [archive,proof,publicKey,origin,name]=process.argv.slice(1), envelope=JSON.parse(fs.readFileSync(proof));
const payload=Buffer.from(envelope.statement,'base64');
if(!crypto.verify(null,payload,fs.readFileSync(publicKey),Buffer.from(envelope.signature,'base64')))process.exit(2);
const value=JSON.parse(payload), raw=fs.readFileSync(archive), custody=JSON.parse(fs.readFileSync(origin));
if(value.fixtureOnly!==true || value.githubOIDC!==false || value.imageQualified!==false ||
 value.productionAuthorized!==false || value.subject.length!==1 || value.subject[0].name!==name ||
 value.subject[0].digest.sha256!==crypto.createHash('sha256').update(raw).digest('hex') ||
 value.archiveBytes!==raw.length || value.sourceSha!==custody.sourceSha || value.sourceTree!==custody.sourceTree ||
 JSON.stringify(value.producer)!==JSON.stringify(custody.producer) ||
 value.custodySha256!==crypto.createHash('sha256').update(fs.readFileSync(origin)).digest('hex'))process.exit(3);
process.stdout.write(JSON.stringify({status:'verified_fixture_unqualified',githubOIDC:false,imageQualified:false}));
"""

# This thin test executable calls the real transfer CLI with its supported
# connection_factory seam. It never constructs an HTTP/socket implementation.
MEMORY_TRANSFER = r'''
import hashlib,io,json,os,sys
from pathlib import Path
sys.path.insert(0,os.environ['FIXTURE_OWNER'])
import private_oci_transfer as owner
configuration=json.loads(Path(os.environ['FIXTURE_PROVIDER']).read_bytes())
class Response:
    def __init__(self,status): self.status=status
    def getheaders(self): return [('x-goog-generation','7'),('content-length','0')]
    def read(self,size): return b''
class Connection:
    def __init__(self): self.headers={};self.sent=bytearray();self.method=None
    def putrequest(self,method,target,**options):
        if method!='PUT' or target!=configuration['target']: raise OSError('fixture scope refusal')
        self.method=method
    def putheader(self,key,value): self.headers[key]=value
    def endheaders(self):
        if self.headers!={'host':owner.HOST,'content-type':'application/octet-stream',
            'x-goog-content-length-range':'1,2147483648','x-goog-if-generation-match':'0',
            'content-length':str(configuration['bytes'])}: raise OSError('fixture header refusal')
    def send(self,chunk): self.sent.extend(chunk)
    def getresponse(self):
        raw=bytes(self.sent)
        if len(raw)!=configuration['bytes'] or hashlib.sha256(raw).hexdigest()!=configuration['sha256']:
            raise OSError('fixture byte refusal')
        Path(configuration['trace']).write_text(json.dumps({'method':self.method,'bytes':len(raw),
            'sha256':hashlib.sha256(raw).hexdigest(),'mode':configuration['mode']}))
        if configuration['mode']=='http_failure': return Response(503)
        Path(configuration['object']).write_bytes(raw)
        if configuration['mode']=='lost_ack': raise OSError('fixture acknowledgement lost')
        return Response(200)
    def close(self): pass
def factory(host,timeout):
    if host!=owner.HOST or not 0<timeout<=30: raise OSError('fixture host refusal')
    path=Path(configuration['calls']); count=int(path.read_text()) if path.exists() else 0
    path.write_text(str(count+1))
    return Connection()
raise SystemExit(owner.main(connection_factory=factory,clock=lambda:1792843200.0))
'''


class FailureFlow:
    def __init__(self, root, **layout_options):
        self.root = Path(root).resolve()
        self.workspace = self.root / "workspace"
        self.workspace.mkdir(mode=0o700)
        (self.workspace / "tooling").symlink_to(REPO, target_is_directory=True)
        base = self.root / "fixture"
        base.mkdir(mode=0o700)
        self.f = Fixture(base, **layout_options)
        self.runner = self.root / "runner"
        self.runner.mkdir(mode=0o700)
        target = self.runner / "fork-release"
        self.f.inputs.rename(target)
        self.f.inputs = target
        self.f.oci = target / "oci/default"
        self.f.layout.directory = self.f.oci
        self.f.manifest, self.f.inventory, self.f.metadata, self.f.resources = (
            target / name for name in ("manifest.json", "patch-inventory.json", "build-metadata.json", "resources.json"))
        self.original_metadata = self.f.metadata.read_text()
        self.f.metadata.unlink()  # The actual workflow capture must create it.
        self.f.out = self.runner / "private-archive"
        self.f.receipt = Path(str(self.f.out) + "-retention.json")
        self.workflow = WORKFLOW_FILE.read_text()
        self.steps = NS(identity=NS(outputs=NS(private_retention="true", private_workflow_sha=WORKFLOW)),
            build=NS(outcome="success"), resources=NS(outcome="success"),
            resource_finish=NS(outcome="success"), private_metadata=NS(outcome="skipped"),
            scope=NS(outputs=NS(enabled="true")), prepare=NS(outcome="skipped"))
        self.trace = []
        self.proof = self.root / "fixture-attestation.json"
        self.provider_object = self.root / "fake-private-object"
        self.provider_trace = self.root / "provider-trace.json"
        self.provider_calls = self.root / "provider-calls"
        self.retained = None

    def env(self, **changes):
        return {**os.environ, "RUNNER_TEMP": str(self.runner), "SOURCE_SHA": packer.SOURCE,
            "SOURCE_TREE": packer.TREE, "WORKFLOW_SHA": WORKFLOW, "TOOLING_SHA": WORKFLOW,
            "ACTUAL_WORKFLOW_SHA": WORKFLOW, "APPROVED_WORKFLOW_SHA": WORKFLOW,
            "GITHUB_SHA": WORKFLOW, "GITHUB_REPOSITORY": "fr-meyer/openclaw", "GITHUB_ACTOR": "fr-meyer",
            "GITHUB_EVENT_NAME": "push", "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
            "BUILT_AT": BUILT, "OCI_DIGEST": self.f.index, "ORIGINAL_BUILD_METADATA": self.original_metadata,
            "MANIFEST": str(self.f.manifest), "INVENTORY": str(self.f.inventory),
            "BUILD_METADATA": str(self.f.metadata), "RESOURCES": str(self.f.resources),
            "OCI_DIRECTORY": str(self.f.oci), "OUTPUT_DIRECTORY": str(self.f.out),
            "GITHUB_ACTION_PATH": str(ACTION.parent), **changes}

    def bash(self, code, **changes):
        return subprocess.run(["/bin/bash", "-c", code], cwd=self.workspace, env=self.env(**changes),
                              capture_output=True, text=True, timeout=15)

    def privacy(self):
        if "continue-on-error:" in step(self.workflow, "Inspect all OCI layers and metadata before native smoke or publication"):
            raise AssertionError("privacy refusal cannot be treated as successful job state")
        result = self.bash(body(step(self.workflow, "Inspect all OCI layers and metadata before native smoke or publication")))
        self.trace.append(("privacy", result.returncode))
        receipt = json.loads((self.runner / "fork-release/privacy.json").read_bytes())
        return result, receipt

    def prepare(self, *, helper_root=None):
        metadata = step(self.workflow, "Capture original hosted build metadata for private retention")
        assert selected(metadata, self.steps, successful=False)
        captured = self.bash(body(metadata))
        self.trace.append(("metadata", captured.returncode))
        self.steps.private_metadata.outcome = "success" if captured.returncode == 0 else "failure"
        caller = step(self.workflow, "Retain private OCI archive")
        assert selected(caller, self.steps, successful=False)
        scope_output = self.root / "scope-output"
        scope = self.bash(body(action_step("Check separately authorized private scope")), GITHUB_OUTPUT=str(scope_output), RETAIN_ENABLED="true")
        self.trace.append(("scope", scope.returncode))
        assert scope.returncode == 0 and scope_output.read_text() == "enabled=true\n"
        assert selected(action_step("Prepare exact opaque private archive"), self.steps, successful=True)
        output = self.root / "prepare-output"
        values = {"GITHUB_OUTPUT": str(output)}
        if helper_root is not None:
            values["GITHUB_ACTION_PATH"] = str(helper_root)
            values["PYTHONPATH"] = str(OWNER)
        result = self.bash(body(action_step("Prepare exact opaque private archive")), **values)
        self.trace.append(("prepare", result.returncode))
        self.steps.prepare.outcome = "success" if result.returncode == 0 else "failure"
        self.outputs = dict(line.split("=", 1) for line in output.read_text().splitlines()) if output.exists() else {}
        return result

    def attest(self):
        assert selected(action_step("Attest retained private OCI archive"), self.steps, successful=self.steps.prepare.outcome == "success")
        section = action_step("Attest retained private OCI archive")
        name = next(line.split(": ", 1)[1] for line in section.splitlines() if line.strip().startswith("subject-name:"))
        digest_template = next(line.split(": ", 1)[1] for line in section.splitlines() if line.strip().startswith("subject-digest:"))
        digest = digest_template.replace("${{ steps.prepare.outputs.sha256 }}", self.outputs["sha256"])
        authority = self.root / "fixture-authority"
        authority.mkdir(mode=0o700)
        self.private_key, self.public_key = authority / "private", authority / "public"
        self.node(KEYGEN, self.private_key, self.public_key, check=True)
        origin = self.f.out / "origin/build-origin.json"
        self.node(SIGN, self.f.out / "retained-oci.tar", digest, name, origin, self.private_key, self.proof, check=True)
        verified = self.node(VERIFY, self.f.out / "retained-oci.tar", self.proof, self.public_key, origin, name)
        assert verified.returncode == 0, verified.stderr
        self.trace.append(("fixture_attest", verified.returncode))
        return json.loads(verified.stdout)

    def node(self, code, *args, check=False):
        node = shutil.which("node")
        assert node is not None, "Node crypto fixture requires the configured CI Node runtime"
        return subprocess.run([node, "-e", code, *map(str, args)], cwd=self.workspace,
            capture_output=True, text=True, timeout=10, check=check)

    def transfer(self, *, mode="ack", mutation=None):
        from urllib.parse import urlencode, urlsplit
        archive = self.f.out / "retained-oci.tar"
        object_name = f"oci-quarantine/v2026.10.5/{packer.SOURCE}/fixture/retained-oci.tar"
        query = {"X-Goog-Algorithm": "GOOG4-RSA-SHA256",
            "X-Goog-Credential": "fixture-signer@fixture-project.iam.gserviceaccount.com/20261024/auto/storage/goog4_request",
            "X-Goog-Date": "20261024T120000Z", "X-Goog-Expires": "600",
            "X-Goog-SignedHeaders": transfer.PUT_HEADERS, "X-Goog-Signature": "b" * 512}
        url = f"https://{transfer.HOST}/fixture-private-bucket/{object_name}?{urlencode(query)}"
        envelope = {"schema": "openclaw.private-oci-capability.v1", "sourceSha": packer.SOURCE,
            "workflowSha": WORKFLOW, "bucket": "fixture-private-bucket", "object": object_name,
            "signer": "fixture-signer@fixture-project.iam.gserviceaccount.com", "url": url}
        if mutation == "scope":
            envelope["object"] = object_name.replace("/fixture/", "/different/")
        elif mutation == "method":
            query["X-Goog-SignedHeaders"] = "host"
            query["generation"] = "7"
            envelope["url"] = url.split("?", 1)[0] + "?" + urlencode(query)
        elif mutation == "hash":
            data = bytearray(archive.read_bytes()); data[-1] ^= 1; archive.write_bytes(data)
        result = json.loads(self.f.receipt.read_bytes())
        configuration = {"target": urlsplit(url).path + "?" + urlsplit(url).query,
            "bytes": result["archiveBytes"], "sha256": result["archiveSha256"], "mode": mode,
            "trace": str(self.provider_trace), "object": str(self.provider_object), "calls": str(self.provider_calls)}
        control = self.root / "provider.json"
        control.write_text(json.dumps(configuration)); control.chmod(0o600)
        helper_root = self.root / "transfer-adapter"
        action_path = helper_root / ".github/actions/retain-private-oci"
        action_path.mkdir(parents=True)
        helper = helper_root / "scripts/fork-release/private_oci_transfer.py"
        helper.parent.mkdir(parents=True)
        helper.write_text(MEMORY_TRANSFER)
        assert selected(action_step("Transfer only the approved private object"), self.steps, successful=True)
        offered = self.bash(body(action_step("Transfer only the approved private object")),
            GITHUB_ACTION_PATH=str(action_path), OCI_UPLOAD_ENVELOPE=json.dumps(envelope),
            FIXTURE_OWNER=str(OWNER), FIXTURE_PROVIDER=str(control))
        self.trace.append(("private_offer", offered.returncode))
        data = json.loads(offered.stdout)
        if offered.returncode == 0 and data.get("status") == "transferred":
            self.retained = data
        self.transfer_adapter = helper
        self.transfer_control = control
        return offered, data

    def retry_same_transfer(self):
        plan = self.f.out / "transfer-plan.json"
        plan_hash = hashlib.sha256(plan.read_bytes()).hexdigest()
        configuration = json.loads(self.transfer_control.read_bytes())
        capability = "https://" + transfer.HOST + configuration["target"]
        return subprocess.run([sys.executable, "-B", str(self.transfer_adapter), "put",
            "--plan", str(plan), "--plan-sha256", plan_hash,
            "--capability-env", "FIXTURE_PRIVATE_CAPABILITY",
            "--archive", str(self.f.out / "retained-oci.tar"),
            "--receipt", str(self.f.out / "transfer.json")], cwd=self.workspace,
            env=self.env(FIXTURE_OWNER=str(OWNER), FIXTURE_PROVIDER=str(self.transfer_control),
                         FIXTURE_PRIVATE_CAPABILITY=capability),
            capture_output=True, text=True, timeout=10)

    def forbidden_stages(self):
        for name in ("Verify OCI bytes and smoke that exact image", "Bind hosted qualification receipts and export decision",
                     "Prepare and verify the bounded public artifact", "Retain the exact tested OCI payload and public receipt"):
            assert not selected(step(self.workflow, name), self.steps, successful=False), name
        assert not any(name in {"native", "public_export"} for name, _ in self.trace)

    def limited_helper(self, limit=None, *, writer_fault=False):
        root = self.root / "prepare-adapter"
        action_path = root / ".github/actions/retain-private-oci"
        action_path.mkdir(parents=True)
        helper = root / "scripts/fork-release/private_oci_bundle.py"
        helper.parent.mkdir(parents=True)
        script = "import sys\nsys.path.insert(0," + repr(str(OWNER)) + ")\nimport private_oci_bundle as owner\n"
        if writer_fault:
            script += ("original=owner.bundle.BoundedWriter.write\ndef fail(self,data):\n original(self,data)\n raise OSError('fixture local write failure')\nowner.bundle.BoundedWriter.write=fail\n")
        else:
            script += ("original=owner.prepare_from_build\ndef limited(*args,**kwargs):\n return original(*args,limit=" + str(limit) + ",**kwargs)\nowner.prepare_from_build=limited\n")
        helper.write_text(script + "raise SystemExit(owner.main())\n")
        return action_path


class PrivateOciFailurePathTests(unittest.TestCase):
    @contextmanager
    def flow(self, **options):
        with tempfile.TemporaryDirectory() as root:
            yield FailureFlow(root, **options)

    def rejected_subject(self):
        return {"provenance": lambda statement: statement["subject"][0]["digest"].update(sha256="f" * 64)}

    def assert_unqualified(self, flow, result):
        self.assertFalse(result.get("imageQualified", False))
        self.assertFalse(result["productionAuthorized"])
        flow.forbidden_stages()
        self.assertFalse((flow.runner / "fork-release/receipt.json").exists())
        self.assertFalse((flow.runner / "fork-hosted-bundle.json").exists())

    def test_rejected_provenance_reaches_real_opaque_archive_fixture_attestation_and_private_offer(self):
        with self.flow(**self.rejected_subject()) as flow:
            process, refusal = flow.privacy()
            self.assertEqual(process.returncode, 1)
            self.assertEqual(refusal["refusal"], "provenance_subject_mismatch")
            prepared = flow.prepare()
            self.assertEqual(prepared.returncode, 0, prepared.stdout + prepared.stderr)
            retained = json.loads(flow.f.receipt.read_bytes())
            self.assertFalse(retained["qualified"])
            self.assertEqual(retained["retentionValidation"], "opaque_byte_inventory")
            self.assertEqual(flow.f.verify(retained)["archiveSha256"], retained["archiveSha256"])
            proof = flow.attest()
            self.assertEqual(proof["status"], "verified_fixture_unqualified")
            offered, result = flow.transfer()
            self.assertEqual(offered.returncode, 0, offered.stdout + offered.stderr)
            self.assertEqual(result["remoteOutcome"], "put_acknowledged")
            self.assertEqual(flow.provider_object.read_bytes(), (flow.f.out / "retained-oci.tar").read_bytes())
            self.assertEqual(result["archiveSha256"], retained["archiveSha256"])
            self.assertEqual(result["archiveBytes"], retained["archiveBytes"])
            self.assertEqual(flow.provider_calls.read_text(), "1")
            self.assert_unqualified(flow, result)
            self.assertEqual(flow.trace, [("privacy", 1), ("metadata", 0), ("scope", 0),
                ("prepare", 0), ("fixture_attest", 0), ("private_offer", 0)])

    def test_malformed_inner_index_is_retained_without_image_qualification(self):
        with self.flow() as flow:
            (flow.f.oci / "index.json").write_bytes(b"not JSON")
            process, refusal = flow.privacy()
            self.assertEqual(process.returncode, 1)
            self.assertEqual(refusal["refusal"], "malformed_json")
            self.assertEqual(flow.prepare().returncode, 0)
            flow.attest()
            offered, result = flow.transfer()
            self.assertEqual(offered.returncode, 0)
            with tarfile.open(flow.f.out / "retained-oci.tar", "r:") as archive:
                self.assertEqual(archive.extractfile("oci/default/index.json").read(), b"not JSON")
            self.assert_unqualified(flow, result)

    def test_non_oci_namespace_missing_root_and_links_never_reach_attestation_or_offer(self):
        for mutation in ("missing-layout", "unexpected-name", "symlink"):
            with self.subTest(mutation=mutation), self.flow(**self.rejected_subject()) as flow:
                marker = flow.root / "unrelated-owned-marker"
                marker.write_bytes(b"preserve fixture")
                if mutation == "missing-layout":
                    (flow.f.oci / "oci-layout").unlink()
                elif mutation == "unexpected-name":
                    (flow.f.oci / "unexpected-name").write_bytes(b"not OCI namespace")
                else:
                    (flow.f.oci / "blobs/sha256" / ("e" * 64)).symlink_to(marker)
                self.assertEqual(flow.privacy()[0].returncode, 1)
                process = flow.prepare()
                self.assertNotEqual(process.returncode, 0)
                self.assertFalse(selected(action_step("Attest retained private OCI archive"), flow.steps, successful=False))
                self.assertFalse(selected(action_step("Transfer only the approved private object"), flow.steps, successful=False))
                self.assertFalse((flow.f.out / "retained-oci.tar").exists())
                self.assertFalse((flow.f.out / ".partial").exists())
                self.assertFalse(flow.proof.exists())
                self.assertFalse(flow.provider_trace.exists())
                self.assertFalse(flow.f.receipt.exists())
                self.assertEqual(marker.read_bytes(), b"preserve fixture")
                self.assertIsNone(flow.retained)
                flow.forbidden_stages()

    def test_header_inclusive_size_bound_and_partial_write_failure_cleanup_only_owned_output(self):
        for mode in ("headers", "write"):
            with self.subTest(mode=mode), self.flow(**self.rejected_subject()) as flow:
                self.assertEqual(flow.privacy()[0].returncode, 1)
                # Capture original metadata through its real workflow owner once;
                # use a second owned operation for the low-limit failure below.
                self.assertEqual(flow.bash(body(step(flow.workflow, "Capture original hosted build metadata for private retention"))).returncode, 0)
                reference = flow.f.prepare()
                with tarfile.open(reference["archivePath"], "r:") as archive:
                    payload_bytes = sum(member.size for member in archive)
                self.assertLess(payload_bytes, reference["archiveBytes"])
                self.assertEqual(packer.MAX_BYTES, 2147483648)
                reference_bytes = Path(reference["archivePath"]).read_bytes()
                old = flow.f.out
                flow.f.out = flow.runner / "failed-private-archive"
                flow.f.receipt = Path(str(flow.f.out) + "-retention.json")
                flow.f.metadata.unlink()  # New actual metadata capture is exclusive.
                helper = flow.limited_helper(payload_bytes, writer_fault=mode == "write")
                process = flow.prepare(helper_root=helper)
                self.assertNotEqual(process.returncode, 0)
                self.assertFalse((flow.f.out / ".partial").exists())
                self.assertFalse((flow.f.out / "retained-oci.tar").exists())
                self.assertFalse(flow.proof.exists())
                self.assertFalse(flow.provider_trace.exists())
                self.assertFalse(flow.f.receipt.exists())
                if mode == "headers":
                    actual_payload = sum(path.stat().st_size for path in (flow.f.out / "origin").iterdir()) + sum(
                        path.stat().st_size for path in flow.f.oci.rglob("*") if path.is_file())
                    self.assertEqual(actual_payload, payload_bytes)
                self.assertEqual((old / "retained-oci.tar").read_bytes(), reference_bytes)
                self.assertIsNone(flow.retained)
                flow.forbidden_stages()

    def test_hash_get_capability_and_scope_changes_fail_before_provider(self):
        for mutation in ("hash", "method", "scope"):
            with self.subTest(mutation=mutation), self.flow(**self.rejected_subject()) as flow:
                self.assertEqual(flow.privacy()[0].returncode, 1)
                self.assertEqual(flow.prepare().returncode, 0)
                flow.attest()
                offered, result = flow.transfer(mutation=mutation)
                self.assertNotEqual(offered.returncode, 0)
                self.assertEqual(result["status"], "failed")
                self.assertFalse(flow.provider_trace.exists())
                self.assertFalse(flow.provider_object.exists())
                self.assertFalse(flow.provider_calls.exists())
                self.assertIsNone(flow.retained)
                self.assert_unqualified(flow, result)
                if mutation == "hash":
                    origin = flow.f.out / "origin/build-origin.json"
                    verification = flow.node(VERIFY, flow.f.out / "retained-oci.tar", flow.proof,
                        flow.public_key, origin, "retained-oci.tar")
                    self.assertNotEqual(verification.returncode, 0)

    def test_failed_and_lost_ack_upload_preserve_unknown_attempt_and_never_claim_retained(self):
        for mode in ("http_failure", "lost_ack"):
            with self.subTest(mode=mode), self.flow(**self.rejected_subject()) as flow:
                self.assertEqual(flow.privacy()[0].returncode, 1)
                self.assertEqual(flow.prepare().returncode, 0)
                flow.attest()
                offered, result = flow.transfer(mode=mode)
                self.assertNotEqual(offered.returncode, 0)
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["remoteOutcome"], "unknown")
                self.assertIsNone(flow.retained)
                marker = flow.f.out / "transfer.json.attempt.json"
                receipt = flow.f.out / "transfer.json"
                before = (marker.read_bytes(), receipt.read_bytes(), flow.provider_trace.read_bytes())
                self.assertTrue((flow.f.out / "retained-oci.tar").exists())
                remote_before = flow.provider_object.read_bytes() if flow.provider_object.exists() else None
                if mode == "lost_ack":
                    self.assertEqual(remote_before, (flow.f.out / "retained-oci.tar").read_bytes())
                # Retry the actual owner against its same reservation, not a new
                # receipt name: it must refuse before the provider is called.
                retry = flow.retry_same_transfer()
                self.assertNotEqual(retry.returncode, 0)
                self.assertEqual(json.loads(retry.stdout)["reason"], "receipt_exists")
                self.assertEqual(flow.provider_calls.read_text(), "1")
                attempt = json.loads(marker.read_bytes())
                self.assertEqual(attempt["remoteOutcome"], "not_attempted")
                self.assertEqual(json.loads(receipt.read_bytes())["remoteOutcome"], "unknown")
                self.assertEqual((marker.read_bytes(), receipt.read_bytes(), flow.provider_trace.read_bytes()), before)
                self.assertEqual(flow.provider_object.read_bytes() if flow.provider_object.exists() else None, remote_before)
                self.assert_unqualified(flow, result)


if __name__ == "__main__":
    unittest.main()
