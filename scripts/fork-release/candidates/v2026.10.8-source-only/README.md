# Future 2026.10.8 synthetic source validation

This candidate is unqualified. The npm 12.2.1 lock was derived once in the
reviewed secretless preparation job; derivation is not test qualification.

One fresh round selects all 15 profiles. Admission is capped at 30 minutes,
individual profiles at their fixed reviewed caps, final aggregation at 10
minutes, and at most three source jobs run concurrently. All operations must
fit the October 30 00:03:19 UTC deadline. The approved npm stage allows 1,337
additional runner-minutes including one targeted correction and incidental
jobs, within the cumulative US$0.30 limit including tax allowance.

Only public source and synthetic fixtures are allowed. No release image,
Docker/OCI build, GCP/SDK use, private data, live provider credentials, new
secrets, merge or production deployment is authorized. Original failures and
previous candidate results remain under their original identities.

The historical preparation.json, settled-usage.json and upstream-verification
records keep their original source identities. Current operational bindings
are source-request.json, manifest.json, patch-inventory.json,
npm-settled-usage.json and lock-preparation-proof.json.
