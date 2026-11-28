"""Test the exact reviewed-owner hook without importing its operational module."""
import ast
import hashlib
import importlib.util
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).parents[1]
HOOK_PATH = Path(__file__).with_name("assemble_shared_owner_hook.py")
if not HOOK_PATH.is_file():
    HOOK_PATH = ROOT / "shared-owner-hook/assemble_shared_owner_hook.py"
S = importlib.util.spec_from_file_location("shared_hook", HOOK_PATH)
HOOK = importlib.util.module_from_spec(S); S.loader.exec_module(HOOK)
BASE = Path("evidence/v108-preparation-20261027/local-integration-r1/pipeline-preparation-r1/activation-r1/successor-remediation-r1/five-gate-repair-r1/source-fetch-stage-r1/re2js-followup-r1/crabline-successor-activation-r1/driver/pipeline/scripts/fork-release/source_validation_v108.py")


# Public CI has the exact reviewed hooked owner, not a duplicate pristine373KB
# fixture. Reverse only the known logging diff and verify its original whole-file
# digest before the existing apply/AST tests; local evidence uses the original.
def baseline_bytes():
    if BASE.is_file():
        return BASE.read_bytes()
    current = Path(__file__).with_name("source_validation_v108.py").read_bytes()
    if hashlib.sha256(current).hexdigest() != "d2e014f20f5227b183ea217d9874ef7159c90a894debe5a6581bd4696145f965":
        raise ValueError("shared_owner.reviewed_current_pin")
    text = current.decode().replace(HOOK.HELPER, "", 1)
    text = text.replace("def bootstrap_pnpm(home, env, request=None, *, operation_identity=None):",
        "def bootstrap_pnpm(home, env, request=None):", 1)
    text = text.replace("source_sha, source_tree, operation_campaign = operation_identity_for(request, operation_identity)",
        "source_sha, source_tree = source_identity_for(request)", 1)
    start = text.index("def bootstrap_pnpm("); end = text.index("\nclass ProfileInterrupted", start)
    text = text[:start] + text[start:end].replace('"campaignId": operation_campaign', '"campaignId": CAMPAIGN') + text[end:]
    text = text.replace('source_sha, source_tree, operation_campaign = operation_identity_for(\n'
        '        context.get("request"), context.get("operationIdentity"))',
        'source_sha, source_tree = source_identity_for(context.get("request"))', 1)
    start = text.index("def phase_process("); end = text.index("\ndef run_commands", start)
    text = text[:start] + text[start:end].replace('"campaignId": operation_campaign', '"campaignId": CAMPAIGN') + text[end:]
    raw = text.encode()
    if hashlib.sha256(raw).hexdigest() != HOOK.BASE_SHA256:
        raise ValueError("shared_owner.reconstructed_baseline_pin")
    return raw


def extracted_identity():
    source = HOOK.apply(baseline_bytes()).decode()
    tree = ast.parse(source)
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "operation_identity_for")
    def need(ok, code):
        if not ok: raise ValueError(code)
    namespace = {"re": re, "need": need, "CAMPAIGN": "historical-campaign",
        "source_identity_for": lambda request: ("historical-sha", "historical-tree")}
    exec(compile(ast.Module(body=[node], type_ignores=[]), "reviewed-identity-excerpt", "exec"), namespace)
    return namespace["operation_identity_for"], tree


class SharedOwnerHookTests(unittest.TestCase):
    def test_historical_default_identity_and_campaign_unchanged(self):
        identity, _ = extracted_identity()
        self.assertEqual(identity(), ("historical-sha", "historical-tree", "historical-campaign"))

    def test_exact_new_logging_identity(self):
        identity, _ = extracted_identity()
        value = {"campaignId": "future-v109-grouped-validation-20261030", "sourceSha": "a"*40, "sourceTree": "b"*40}
        self.assertEqual(identity(None, value), ("a"*40, "b"*40, value["campaignId"]))

    def test_arbitrary_campaign_or_fields_refuse(self):
        identity, _ = extracted_identity()
        for change in ({"campaignId": "arbitrary"}, {"sourceSha": "not-sha"}, {"execute": "anything"}):
            value = {"campaignId": "future-v109-grouped-validation-20261030", "sourceSha": "a"*40, "sourceTree": "b"*40}
            value.update(change)
            with self.subTest(change=change), self.assertRaises(ValueError): identity(None, value)

    def test_only_three_functions_change_and_no_history_policy(self):
        before = ast.parse(baseline_bytes().decode()); after = ast.parse(HOOK.apply(baseline_bytes()).decode())
        def nodes(tree):
            return {getattr(node, "name", "assignment-"+str(i)): ast.dump(node, include_attributes=False)
                for i,node in enumerate(tree.body)}
        old, new = nodes(before), nodes(after)
        # Compare existing named functions and all non-function source spans:
        # insertions shift AST positions but do not alter historical policies.
        changed = {name for name in old if name in new and old[name] != new[name] and not name.startswith("assignment-")}
        self.assertEqual(changed, {"bootstrap_pnpm", "phase_process"})
        old_other=[ast.dump(n,include_attributes=False) for n in before.body if not isinstance(n,ast.FunctionDef)]
        new_other=[ast.dump(n,include_attributes=False) for n in after.body if not isinstance(n,ast.FunctionDef)]
        self.assertEqual(old_other,new_other)

    def test_nonmatching_baseline_never_patches(self):
        with self.assertRaisesRegex(ValueError,"baseline_pin"): HOOK.apply(baseline_bytes()+b"\n")

    def test_bootstrap_optional_hook_preserves_old_signature_defaults(self):
        _,tree=extracted_identity()
        bootstrap=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='bootstrap_pnpm')
        self.assertEqual([a.arg for a in bootstrap.args.args],['home','env','request'])
        self.assertEqual(ast.dump(bootstrap.args.defaults[0]),'Constant(value=None)')
        self.assertEqual([a.arg for a in bootstrap.args.kwonlyargs],['operation_identity'])
        self.assertEqual(ast.dump(bootstrap.args.kw_defaults[0]),'Constant(value=None)')


if __name__=='__main__':unittest.main()
