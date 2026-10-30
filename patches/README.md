# Temporary dependency patches

## Zod consumer migration

[GHSA-mrhx-c7xc-m3w5](https://github.com/advisories/GHSA-mrhx-c7xc-m3w5)
is repaired without an audit exception. Native Zod consumers use `4.6.6`.
The exact-version Zod patch also applies the upstream early collection-bound
behavior to the retained `zod/v3` compatibility parser in its ESM, CommonJS,
and TypeScript sources. Oversized bounded arrays and sets reject before
visiting children; valid, minimum-only and unbounded inputs retain their
existing behavior. The v3 compatibility API remains available for MCP schemas.
This does not impose a global size limit on unbounded schemas.

`@a2ui/lit@0.12.0` and `@a2ui/web_core@0.12.0` are migrated together to
native Zod v4, with generated declarations and source maps updated from their
published TypeScript sources. The version-qualified dependency overrides are
required in addition to the package patches: changing an installed manifest
does not select a different dependency graph. Only A2UI's superseded
`zod-to-json-schema` dependency is removed; MCP and Mistral still use that
converter, with its declared mixed peer range preserved. Canvas disables Zod's
JIT capability probe to respect its strict CSP. Public catalog generation and
binder/reference traversal require their own compatibility regressions; a
plain Zod-version override is insufficient.
Function parameter schemas resolve their own local definitions, with the
existing catalog-document fallback retained. The inherited recursive-component
and theme reconstruction limits in `Catalog.fromSchema` remain unchanged;
this patch does not add a general JSON Schema reconstruction engine.
Recursive function regressions cover legacy capabilities, standalone argument
schemas, and catalog-level references. Native union diagnostics retain the
full parent path without mutating the original issues.

`@discord/embedded-app-sdk@2.5.0` replaces both embedded legacy parsers with
the official native-v4 dependency. Its affected declarations are regenerated
from upstream tag `v2.5.0`, commit
`14264eccbf9e68d5d58c1aadbc7579e003e0dce6`. RPC command results,
unsupported-scope fallback, omitted envelope data and `SDKError` identity remain
covered by the regression. Raw validation errors use native-v4 `issues` and
paths; the old Zod `errors` alias is intentionally absent. OpenClaw's Activity
consumer uses the SDK's constructor, readiness and authorization methods, not
that alias.

After regeneration, use stock pnpm with the frozen lock and verify the actual
installed target hashes. pnpm hashes normalized LF patch bytes; package
integrities and patch hashes are both retained in the lock. Do not edit
installed dependencies, mask their versions, remove the strict audit, or apply
a blanket converter override. Docker already copies these patches before its
frozen dependency installation.

Focused checks after a frozen or isolated installation:

```sh
node --test test/zod-container-bounds.test.mjs
node --test test/discord-native-zod-regression.test.mjs
node --test test/a2ui-native-zod-regression.test.mjs
node --test test/mcp-nowistay-sdk-regression.test.mjs
node scripts/run-vitest.mjs run test/scripts/zod-legacy-closure.test.ts test/scripts/check-package-patches.test.ts --maxWorkers=1
node scripts/pre-commit/pnpm-audit-prod.mjs --audit-level=high
```

For an isolated installed fixture, `ZOD_TEST_PROJECT`,
`DISCORD_SDK_TEST_PROJECT`, `A2UI_TEST_PROJECT` and `NOWISTAY_COMPAT_SDK_ROOT` explicitly select
that installation. They must identify the tested pinned packages, never a
substitute schema implementation. The A2UI 0.12 regression also requires
`A2UI_TEST_VALIDATOR_PROJECT` pointing to an installed Ajv 8.20.0 test fixture
for actual JSON Schema validation; it is not a runtime dependency. These native
Node tests are explicit prerequisites, outside the TS-only Vitest discovery.
Remove each temporary patch, its exact
registration and guard allowance only when a supported upstream consumer
release passes the corresponding runtime/type, catalog, browser and audit
checks without it. A passing audit alone does not prove those contracts.

Keep existing insertion anchors when extending these patches: pnpm 12 can apply a zero-context, zero-length insertion one line early. After regeneration and installation, verify installed files against the patch's target blob hashes before testing.

`@awesome.me/webawesome@3.13.0` retains its approved dropdown, submenu, select, tooltip, and animation lifecycle repairs. The dropdown initializes focus after its popup becomes usable, before joining animation cleanup or completion, and preserves a newer composed focus target during popup rendering. Freshly mounted open menus also join the popup's initial anchor resolution before focusing; already anchored menus retain their existing visibility and native occlusion across reopen. Initial-focus handlers can close or disconnect the menu; the existing transition owner fences those reentrant paths before starting an animation. Opening completion never resets a newer item, submenu, or outside focus. Both published distributions carry the same owner. The tooltip trigger handler uses upstream's `containsComposedNode` helper to retain the 3.13 fix for hover across Shadow DOM slots; the port also preserves upstream overflow-tag size and pill styling.

Remove the dropdown focus hunk when an upstream release passes `ui/src/e2e/chat-attachment-focus.e2e.test.ts`, the unchanged platform attachment menu suite, and both `web-awesome-dropdown*.browser.test.ts` lifecycle suites without a consumer animation wait. These tests use real CSS animation boundaries, native keyboard input, and the actual browser filechooser; mobile identities are emulated, not native OS-picker certification. Retain the other patch owners until their respective regressions pass upstream.

The popup disposes its previous Floating UI subscription before starting another and releases the new subscription if a synchronous reposition listener disconnects or deactivates it. Remove both popup hunks when an upstream release passes the public resize/disconnect lifecycle cases in `ui/src/components/web-awesome.test.ts` without retaining resize work after removal.

`chrome-devtools-mcp@1.10.1` has an approved exact-version snapshot-identity patch, backported from [ChromeDevTools/chrome-devtools-mcp#2788](https://github.com/ChromeDevTools/chrome-devtools-mcp/pull/2788) at `06c8d4bc44f68bde8bd3fcd97dcc47375df81fe9` and forward-ported onto tag commit `e52c6b59b476c5e04d8dd9fd4bd017ba3b3d65df`. Stable IDs include the frame's captured CDP session and document generation; ambiguous IDs stay capture-local, and stale lazy handles cannot resolve into a replacement renderer. Frame-local lookup and retained extra handles preserve actions and labeled screenshots. The 1.10.1 CSS-style lookup resolves the same guarded handle and stays within its captured renderer, failing closed when the embedded DevTools target cannot represent a cross-renderer frame. Version 1.10.1 already exports its bundled `CdpFrame`, so the patch changes only the snapshot owner and its DOM-result caller. Original license notices remain intact, with modifications recorded in `build/src/OPENCLAW_PATCH_NOTICE.md`.

The published integrity is `sha512-Klw6HWDqHC/XS1JwZldd2r49aUhbUJN9m9Mvcx4SEueIPXtzuQX+QelxAViobv8YUkDZ7HWDrmViR6LeYK0wAw==`; the patch SHA-256 is `d31d6e7e187ea9fd4dad87ed3ad08073c77ffcfddd52bc4761b39a2dfce0ac1e`.

| Target | Published SHA-256 | Patched SHA-256 |
| --- | --- | --- |
| `build/src/TextSnapshot.js` | `f3496989b93d174723fcf394628fabc36936b37e6a815fd85cbe20fba46d5ea0` | `299833ad0e4cfc171a417afaec41df594e4862fe53a7ada6ba160409f979788b` |
| `build/src/McpPage.js` | `d49b2666cb9c6c5b4d7b9130235c476cb8a3af580363ff224796d9dbde99538d` | `47aa13c6b28cc11e1b0883532edea97cfde7563d78d143035850852d09809975` |
| `build/src/third_party/index.js` | `c988e0684584b75e87ae04b768c4f8ae7064401afe5187ec0d4878b2c6833f12` | Unchanged |
| `build/src/OPENCLAW_PATCH_NOTICE.md` | Added | `4bf44b52a80b5860b2160bc83407a5f0dd09f1801c85d0a2b6e4fec26bd7045d` |

The root package bundles this patched dependency so npm installations preserve the same bytes as pnpm source installs. Browser launches the packaged CLI directly with the runtime running OpenClaw, Node or Bun. Remove this patch, its registration, and the patch-specific package checks when a published upstream version passes `pnpm test:e2e:browser-mcp` and the installed-package stdio proof, including renderer replacement, cross-origin frames, cancellation, and snapshot → wait → action.

`@novnc/novnc@1.7.0` has an approved temporary patch for ignored extended-clipboard payloads. The RFB owner consumes the remaining compressed bytes before returning for view-only clients or unsupported clipboard formats. It does not inflate or publish ignored clipboard data, and controlling text clipboard handling stays unchanged. This keeps clipboard bytes from becoming the next RFB message and disconnecting WebVNC.

Remove the noVNC patch, its registration, and its exact-version guard exception when an upstream version passes the Desktop panel and document browser suites (`test/vitest/vitest.ui-e2e.config.ts`) and the live view-only selection/type stress check. The regression uses the real noVNC parser, covers coalesced and fragmented payload delivery, and requires the next framebuffer update without a reconnect.

`matrix-js-sdk@42.4.0` has an approved temporary patch for saved-sync verification replay. Classic sync propagates its existing cache provenance through ordinary client events, and the crypto listener ignores restored events. This preserves room history, sync cursors, ordinary event listeners, fresh verification events, and to-device processing while preventing cached verification requests from restarting after a clean client shutdown. Version 42.4.0 still routes restored events into crypto, so the patch remains necessary.

Remove the Matrix patch, its registration, and its exact-version guard exception when an upstream release passes `node scripts/run-vitest.mjs extensions/matrix/src/matrix/client/file-sync-store.sdk.test.ts` and the full Matrix QA catalog, including the original DM SAS-to-QR sequence. The regression exercises the real SQLite sync store, SDK cache hydration, and crypto event wiring; it observes crypto input rather than substituting for native verification proof.

## Vitest 5.0.5 selected patch

`vitest@5.0.5` is selected. Its unchanged retained pnpm patch is SHA-256
`5ab1f247d7051105fd2967cc6b22e50cb97a289a73d73afbd24cdf4439c40d4d`. The existing frozen fork lock records integrity
`sha512-cPODOMF8YnkiiYtDdHo6n4wWmBrOBBbOIYH2d33M4l3CdNn72h+qMmO6uXffUN6A5AZFXNND/d+krS9mgkXRfg==`; successor CI lock derivation must preserve the selected package
identity. No standalone runner patch is registered. The retired `5.0.1` patch
is not selected or allowed by the current package-patch guard.

The reviewed 5.0.5 rebase changes these nine targets. These are Git blob IDs
recorded in the patch, not SHA-256 integrity values or fresh installed proof:

| Target | Preimage Git blob | Patched Git blob |
| --- | --- | --- |
| `dist/chunks/cac.CLrZKo1g.js` | `ea61b3c5bfa263708d356eefb3b6217af7d301f4` | `1523fcaeb9802e4823922f9de9aed238799c633a` |
| `dist/chunks/cli-api.De07GUeT.js` | `ff6e63043ff8fa0b821d4b0b382d1fd998d85dbb` | `8b527adb355c8e7397939baece62749f3f334d1e` |
| `dist/chunks/index.1TqnEahn.js` | `50dd001b7b24be2eac6f37eeb1929ad4645aa1a9` | `a4942f2ece3dc13bb54142c9809ae19d6401510c` |
| `dist/chunks/index.CK-t0WMg.js` | `bf563f92484d59695a49772f94a6ea68e10bcee2` | `d8bfb9b46212c2cfe2d86a5269e43fc5ac7686e3` |
| `dist/chunks/index.aTZaPVhf.js` | `4c481d259556a3c3c974c9504047df161e7feef3` | `965432354a76ab4d79e10519a886171f26349cd2` |
| `dist/chunks/init-forks.CRxIPOJR.js` | `d405dea2b5c03f70ef94a82d5e4e10c104164154` | `01e6099aabf7fb6e53249327d53d062277f00e52` |
| `dist/chunks/plugin.d.C8mmycim.d.ts` | `b8af1e7401b5b418cd49ab017d9bc3fdbe590ae3` | `09cdb33f80bd1596bf4081b8855f0448b08ff938` |
| `dist/chunks/run.BPv-BBRv.js` | `5c235b31744aebca14b9a79dd0836fa0faa9740f` | `703abcdac3d6196667a6c69509ca5bfd7025fd8b` |
| `dist/node.d.ts` | `fce7738ae75bb25bdf007f95074c964e62186def` | `07e0682338342763adedcc34c713dd38bd61c7a5` |

The retained repairs cover serialized mock resolution, CLI validation without
execution, lockfile-aware cache generations/invalidation, graceful and
already-exited fork settlement, file-backed project roots/names, trailing
runner updates and fake-timer heap ordering. Failed or timed-out cleanup must
still fail; an exited worker cannot be reused. Remove a repair only when the
corresponding stock version passes these existing boundary regressions:

- `test/scripts/vitest-mock-resolution.test.ts`
- `test/scripts/run-vitest-profile.test.ts`
- `test/scripts/vitest-report-owner.test.ts`
- `test/vitest-performance-config.test.ts`
- `test/scripts/vitest-fork-shutdown.test.ts`
- `test/scripts/run-vitest-state-cleanup.test.ts`
- `test/vitest-ui-package-config.test.ts`
- `test/scripts/vitest-runner-task-updates.test.ts`
- `test/scripts/vitest-fake-timers.test.ts`
- `extensions/telegram/src/probe.response-body-timeout.test.ts`

Also retain the original cold Gateway group containing
`authenticated-request-dispatch.lifetime.test.ts`. The actual API-mode
private-file/token denial in `test/v108-remediation-security.test.mjs` is a
separate required regression: the custom lifecycle patch must not weaken the
upstream HTTP filesystem deny policy or substitute for that proof.

Generate/register dependency patches through pnpm in the approved CI lane;
never edit installed dependency files. A frozen installation must apply the
recorded patch and verify installed targets before runtime checks. Local
merge preparation has not executed those tests or regenerated this patch.

`baileys@7.0.0-rc14` needs a two-line adapter for `audio-decode@3.12.0`:
read the first decoded channel from `channelData[0]` and require the matching
3.x peer. Version 3 returns raw channel arrays instead of an AudioBuffer;
Baileys otherwise catches the missing `getChannelData()` method and silently
omits voice-note waveforms. The existing Baileys owner retains waveform
normalization, media preparation, and best-effort decoding errors.

The patch SHA-256 is
`03ae85550381d1bda7d014c9aa9f544ad421d35d745d1167fd5d33f7f715dafb`.
The regression in `extensions/whatsapp/src/baileys-audio.test.ts` prepares a
real Baileys voice-note payload from deterministic PCM and checks its complete
64-byte waveform. Isolated dependency proof also covered Buffer, file, and
stream decoding, WAV and Ogg Opus voice payloads, and malformed-audio handling.
The plugin package owner bundles patched runtime dependencies so installed
WhatsApp plugins retain the adapter. Remove this patch and its registration
when an upstream Baileys version accepts the current decoder and passes the
same voice-note regression.

## 10.9 upstream Zod 3 patch and the selected fork graph

Official 10.9 adds `patches/zod@3.25.76.patch`, SHA-256
`2f14d2000a3645bf519c1a1cc4848a71d55185327a9a976a4f033e7d507b727d`. It is a local Zod-3 adaptation of Colin McDonnell's early
upper-size rejection in upstream commit
`a0ebf970f2d752e5f58527cd2942ff48be4f46bd`
([colinhacks/zod#6652](https://github.com/colinhacks/zod/pull/6652)), not an
upstream Zod-3 release or blanket advisory clearance. That source patch and
its original attribution remain unchanged in this tree.

This fork selects Zod `4.6.6`, whose exact patch applies the same early-abort
intent to the retained `zod/v3` compatibility parser in ESM, CommonJS and
TypeScript. A2UI uses native v4. The Discord SDK's ESM and CommonJS embedded
parser entrypoints are replaced by external v4 bridges, so the upstream six
Zod-3 SDK hunks cannot be appended to those removed parser bodies. The
unchanged selected Discord migration patch is SHA-256
`571102cd0329706f1c9edf2dd5cd7f50bfcb8c4336809c961e0c12f43760ab87`; it also preserves v4 declarations, scope fallback and RPC behavior
covered by the existing native SDK regression.

The retained pre-derivation fork lock contains no `zod@3.25.76` package. The
workspace therefore does not register an unused Zod-3 patch. The upstream
source file is retained but dormant; the guard recognizes only its exact
version/path. CI lock admission must reject a new unpatched Zod-3 resolution,
not assume this dormant file is applied. A graph requiring it needs explicit
reviewed registration or a complete compatible migration before qualification.
Do not use `allowUnusedPatches`, an audit exception or a broad override to hide
that condition. Successor lock generation and installation remain unrun here.

Keep the container-bound, A2UI, Discord, MCP/converter, runtime/type and strict
audit regressions listed above. Early rejection changes oversized bounded
arrays/sets from dirty to aborted before visiting children; valid, unbounded
and minimum-only behavior must remain. Retaining source adaptations is not
proof that every installed copy is fixed. CI graph and installed-package
owners supply that proof.
