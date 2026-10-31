"""Produce the reviewed generic logging-identity hook without changing a checkout.

The historical owner remains authoritative for process ownership, timeout cleanup,
pnpm bootstrap and its historical request policies. The explicit identity affects
only emitted operation facts for the separately admitted 10.9 caller.
"""
import ast
import hashlib

BASE_SHA256 = "c1d597e5aa818b796a3ec211c5aba60f03f3b056a7ced56b85da6c1c11f912f8"
HELPER = '''def operation_identity_for(request=None, operation_identity=None):
    """Logging identity only; the caller must separately admit every operation."""
    if operation_identity is None:
        source_sha, source_tree = source_identity_for(request)
        return source_sha, source_tree, CAMPAIGN
    need(type(operation_identity) is dict and set(operation_identity) ==
        {"campaignId", "sourceSha", "sourceTree"} and
        operation_identity["campaignId"] == "future-v109-grouped-validation-20261030" and
        all(type(operation_identity[k]) is str and
            re.fullmatch(r"[0-9a-f]{40}", operation_identity[k]) is not None
            for k in ("sourceSha", "sourceTree")), "fixed explicit operation identity")
    return (operation_identity["sourceSha"], operation_identity["sourceTree"],
            operation_identity["campaignId"])


'''


def apply(raw):
    if type(raw) is not bytes or hashlib.sha256(raw).hexdigest() != BASE_SHA256:
        raise ValueError("shared_owner.baseline_pin")
    text = raw.decode("utf-8")
    start = text.index("def bootstrap_pnpm(home, env, request=None):")
    end = text.index("\nclass ProfileInterrupted", start)
    old = text[start:end]
    new = old.replace("def bootstrap_pnpm(home, env, request=None):",
        "def bootstrap_pnpm(home, env, request=None, *, operation_identity=None):", 1)
    new = new.replace("source_sha, source_tree = source_identity_for(request)",
        "source_sha, source_tree, operation_campaign = operation_identity_for(request, operation_identity)", 1)
    if new.count('"campaignId": CAMPAIGN') != 1:
        raise ValueError("shared_owner.bootstrap_shape")
    new = new.replace('"campaignId": CAMPAIGN', '"campaignId": operation_campaign')
    text = text[:start] + HELPER + new + text[end:]
    start = text.index("def phase_process(argv, cwd, env, context, phase, ordinal):")
    end = text.index("\ndef run_commands", start)
    old = text[start:end]
    new = old.replace('source_sha, source_tree = source_identity_for(context.get("request"))',
        'source_sha, source_tree, operation_campaign = operation_identity_for(\n'
        '        context.get("request"), context.get("operationIdentity"))', 1)
    if new.count('"campaignId": CAMPAIGN') != 1:
        raise ValueError("shared_owner.phase_shape")
    new = new.replace('"campaignId": CAMPAIGN', '"campaignId": operation_campaign')
    text = text[:start] + new + text[end:]
    ast.parse(text)
    return text.encode("utf-8")
