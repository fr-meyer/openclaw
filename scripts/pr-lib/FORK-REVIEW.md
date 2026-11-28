# Optional fork review evidence

This helper is an explicitly invoked review-evidence producer for the public
repository github.com/fr-meyer/openclaw, numeric repository ID 1309456040.
It is not a merge gate, a GitHub approval, a dispatcher, or authority to merge.
No PR wrapper, workflow, provider, or runtime automatically invokes it.
Existing prepared-review, native CI, repository identity and owner authorization
requirements remain unchanged. A clean receipt does not replace any of them.

## Invocation and trust

Use independently reviewed code from a trusted checkout. Permission to use the
Codex review service must already cover the exact PR source, tests and docs.
Do not invoke it without that disclosure/provider authority. It does not grant
new credentials, spending, execution or publication authority.

The explicit CLI requires --checkout, --repository, --host, --pr, --base-sha and
--head-sha. The checkout must already contain the exact candidate or a proven
tree/diff-equivalent local commit; this helper does not fetch contributor code.
The existing autoreview entry point owns provider execution and isolation.
Candidate code and candidate helper scripts are not executed by this adapter.

The helper binds the public numeric target repository identity, contributor head
repository, PR, base, head, tree, merge-base and full/review diff hashes. It checks
source and live identity again after review and refuses incomplete, filtered,
stale, changed or failed results. Git, gh, Codex and helper hashes are recorded.
Outputs are retained outside the reviewed checkout in a private temporary folder.
The receipt identifies itself as a local operator attestation, not signed provider
proof. Treat its status as evidence only, never as live merge authority.

## Deliberate difference from historical PR21

Historical PR21 wired fresh Codex execution into mandatory final merge admission,
changed fork merge routing, and added autoreview to the anchored wrapper closure.
Those changes are not included here. Existing merge.sh and wrapper-components.txt
remain unchanged, and mandatory-gate shell fixtures are not added. There is no
new requirement to run Codex before an otherwise-qualified fork merge.

The accompanying tests use synthetic provider responses and disposable Git
fixtures. They do not qualify hosted execution, actual Codex behavior or native CI.
