# Frozen runtime qualification packet

This packet is blocked. The unchanged synthetic Doctor migration needs a separate
Node process, which the required runner boundary denies. No supported execution
command or hosted runtime workflow is admitted. All six phases remain NEVER_RUN.

`packet.json` pins the qualified product source, retained Actions image, Node,
Doctor export, four unchanged synthetic inputs and all six argument lists. Its
critical chain joins exact committed source with independently captured image
file hashes and lines. The fixture's migration calls Doctor write admission;
`preserveSourceArtifacts: true` selects a process-backed SQLite snapshot;
`runSqliteReadOnlyWorkerOnce` calls `execFile(process.execPath, argv, ...)`.
Native thread permission cannot authorize that child. Doctor's environment
argument also does not bind staging: a future scratch-only route would need a
global `XDG_CACHE_HOME` inside scratch.

The original Node Permission Model fsync failure remains retained and binding.
Changing confinement alone does not resolve the process incompatibility. Any
proposal changing product code, the frozen fixture or the no-child boundary
needs an explicit scope decision, fresh review and its own exact-source evidence.
No such change, permission removal, native policy probe, image startup, database
operation, dependency download, cloud allocation or publication is performed here.

The analysis tools read image bytes as data. `read-closure-bytes.py` verifies
the previously admitted archive, inventory and client receipt digests, then stores
only regular-file content under flat SHA-256 names. It reproduces no tar paths,
links, permissions or image filesystem. Content capture alone does not establish
every final path binding. `full-catalog-join.py` separately reuses the reviewed,
digest-pinned local 9de validator's saved-layer algorithm to compare all final
identities with the producer inventory; every difference stays explicit.
`static-closure.mjs` uses an already
installed, digest-pinned Acorn parser; it never imports image JavaScript. Its graph
is an exploratory conservative import graph, not a full Node resolver or closed
Worker/native binding admission. Unresolved selectors, Worker facts and parser
limitations remain explicit. `elf-dependencies.py` inspects ELF64 headers and
joins standard-path SONAME candidates; it never invokes ldd or loads libraries.
It does not qualify loader-cache or runtime dlopen behavior.

The image and all earlier failed/interrupted receipts stay unchanged. Native
preload and driver drafts were quarantined outside this packet once the concrete
process incompatibility was found. Their syntax checks are not enforcement proof.

Safe local validation: `python3 -B -m unittest discover -s
scripts/proofs/v98-runtime -p 'test_*.py'`, followed by `git diff --check`.
