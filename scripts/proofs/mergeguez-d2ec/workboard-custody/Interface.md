The companion accepts the core's host-only held `persist` closure:

```js
const custodian = createWorkerCustodian({
  sourceBinding: {sourceBootId, sourceOwnerId, sourceGenerationId, profileSha256},
  python, custodyRoot, executionBootId, sizeLimit: 4 * 1024 * 1024,
});
await custodian.persist(payload, operationId, assertCurrent);
await custodian.close();
```

Construction is dormant. It accepts no caller-selected assurance or module pins.
The fixed `sourceBinding` is cloned and frozen; it records the trusted issuer's
actor/incarnation binding and confers no permission by itself. The core must
capture the immutable `persist` function in its host-only authority, hold the
original actor and connection lease until it settles, and supply the genuine
live admission/epoch/lease `assertCurrent` closure. Calling the companion with a
no-op function is not a validated operational issuer. Ordinary card interfaces
must never receive either the companion or its capture bytes.

Payload is a copied `Uint8Array` containing exactly
`{exported,snapshotBase64,captureInterval}`. The transport limit is 32 MiB. The
default 4 MiB companion quota bounds aggregate packaged members, a stricter
condition than per-file custody. The host validates UTF-8, canonical base64,
snapshot transport header, fixed logical shape, typed values, schema/table/blob
hashes and cutoff. It imports no SQLite or native-memory codec and opens no
SQLite handle. Semantic snapshot/export equality and exact source-schema
acceptance belong to the pinned native worker codec before transfer. Only the
private-gated original actor/lease broker result may enter `persist`; neither
payload metadata nor an arbitrary caller's assertion proves that provenance.

The actual default transport is the frozen `SealedPythonClient`. It verifies and
compiles the pinned helper buffers, then stages four members through existing
descriptor custody, revisioned acceptance ledger and private proof keeper. The
returned record contains only identifiers, hashes, fixed assurance and inert
flags. No raw proof, claims, text, snapshot, path or nonce is returned. A local
60-second acknowledgement deadline bounds bookkeeping; it is not a private
permission grant. Live admission is checked at every side effect and await
boundary. Retirement after staging records reject-only bookkeeping. A queued
acceptance denied before send rejects the known stage. Once acceptance is sent,
an uncertain transport or retired acknowledgement must be reconciled rather
than retried. Malformed acknowledgement leaves an explicit failed call with
sanitized operation/binding context; it cannot yield a successful receipt.
Every sent acceptance transport failure, malformed acceptance acknowledgement
and post-acceptance retirement has code
`PRIVATE_ACKNOWLEDGEMENT_OUTCOME_UNKNOWN`, bounded original error/cleanup codes
and an immutable disposition requiring reconciliation and forbidding retry.
That disposition acknowledges possible durable acceptance rather than
claiming failure or success.
Local closure is checked both before and after each live-source callback, so a
reentrant shutdown prevents subsequent helper construction or sends.

Nine vendor inputs are byte-identical to the accepted logical candidate. Shared
I/O remains frozen v5, SHA256
`ef1f6341e8fbc29c13b3acb873fbc9181f0075f6869c37bc6fa87fba52d6b967`.
There is no automatic publisher revision adoption. Source-file hashes are
custody checks; this companion does not establish deployed JS/interpreter loaded
image identity or the runtime's trusted bootstrap and private issuer.

The author unit checks use synthetic in-memory SQLite only in the test fixture
and codec semantic probe, then host-only transport packaging and a VM-mocked
sealed transport for ordering and sanitization. The semantic negative probe
demonstrates a transport-consistent mismatch is rejected by the codec, while the
host deliberately makes no semantic equality claim. They start no Python
process, private custody tree or native SQLite worker and prove no live runtime
admission. The actual worker → genuine core authority → real sealed descriptor
custody integration remains deferred to the parent's resource coordination.
The frozen helper's previous independent acceptance remains its evidence; this
bridge needs independent exact-source review with the complete new overlay.
