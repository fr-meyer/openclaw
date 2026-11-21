# PR Lifecycle TaskFlow

`pr-lifecycle-taskflow` is an OpenClaw extension for durable, exact-head pull-request review and remediation workflows.

It turns repository events into a bounded TaskFlow that can:

1. admit an allowlisted pull request at an exact base and head SHA;
2. dispatch a review worker with a controller-issued claim;
3. store structured, bounded findings;
4. dispatch an attested remediation worker when findings are actionable;
5. require a new exact-head review after publication;
6. stop at `merge_ready` until an owner supplies a current, scope-bound merge authorization;
7. optionally ask a configured repository broker to merge after every gate is revalidated.

The extension is fail-closed. It does not provide a general-purpose GitHub write tool, raw push route, or worker-callable merge action.

## Safety properties

- **Exact-head binding:** review, remediation, publication, and merge evidence are bound to full commit SHAs.
- **Revision fencing:** owner actions and worker reports must match the current flow revision and worker generation.
- **Actor separation:** reviewer and author identities must be distinct. The author actor must match the author worker agent.
- **Bounded retries:** content retries, infrastructure retries, remediation cycles, and wall-clock lifetime have independent limits.
- **Structured findings:** untrusted review text is bounded and stored as data. Findings must include repository-relative paths before remediation can start.
- **Attested publication:** successful remediation requires test evidence, publisher attestation, and authoritative remote-head confirmation.
- **No implicit merge:** `merge_ready` is a nonterminal approval gate. A separate durable authorization must name the exact repository, PR, base branch, method, policy digest, and validity window.
- **Last-moment reconciliation:** the broker re-reads pull-request identity, review coverage, checks, mergeability, actor, base, and head immediately before a merge.
- **Lease-protected merge:** concurrent merges for the same repository and base branch are serialized by an atomic lock.
- **Private evidence directory:** remediation bindings and evidence remain outside the repository under the configured `remediationRoot`.

## Components

- `src/controller.mjs`: deterministic lifecycle state machine and validation.
- `src/runtime.mjs`: OpenClaw TaskFlow integration, worker dispatch, recovery, notifications, and broker calls.
- `src/http.mjs`: bounded webhook parsing, HMAC verification, and request limits.
- `test/`: controller and runtime regression coverage.

## Configuration

The extension is inert unless `enabled` is true. Paths and identities are configuration, not source constants.

```json
{
  "enabled": true,
  "ownerSessionKey": "agent:owner:main",
  "repositoryBrokerPath": "/opt/openclaw/bin/repository-broker",
  "remediationCommandPath": "/opt/openclaw/bin/pr-lifecycle-remediate",
  "remediationRoot": "/var/lib/openclaw/pr-lifecycle/remediation",
  "githubWebhookSecret": {
    "source": "store",
    "provider": "protected",
    "id": "PR_LIFECYCLE_GITHUB_WEBHOOK_SECRET"
  },
  "brokerEventSecret": {
    "source": "store",
    "provider": "protected",
    "id": "PR_LIFECYCLE_BROKER_EVENT_SECRET"
  },
  "repositories": {
    "example-org/example-repo": {
      "enabled": true,
      "mode": "active",
      "workspace": "/srv/openclaw/repos/example-repo",
      "brokerRepoAlias": "example-repo",
      "baseBranches": ["main"],
      "reviewActor": "review-broker",
      "authorActor": "author-worker",
      "reviewWorkerAgentId": "review-worker",
      "authorWorkerAgentId": "author-worker",
      "fixerModel": "primary-fixer-selector",
      "fixerFallbackModel": "fallback-fixer-selector",
      "publisherBrokerId": "publisher-broker/v1",
      "publisherAttestationRef": "proof:publisher-boundary-review",
      "maxCycles": 2,
      "maxRetries": 2,
      "wallTimeMinutes": 720,
      "maxParallelPrs": 1,
      "allowForks": false
    }
  }
}
```

Use real model selectors and broker commands that are available in your installation. Keep webhook secrets in OpenClaw secret inputs. Do not place credentials, tokens, private keys, or production evidence in repository configuration.

## Remediation profile

Active remediation requires a versioned profile that narrows the author worker to an exact repository and pull-request set. The profile declares:

- seed workspace and worktree root;
- allowed base branches and head pattern;
- allowed write paths;
- required test paths;
- argument-vector validation commands;
- publication route and commit subject;
- required attestation policy.

The controller rejects profile drift, uncovered finding paths, missing executables, incomplete test-path coverage, or a publisher boundary without both an identifier and proof reference.

## Optional automatic merge

Automatic merge remains disabled when `autoMergeBaseBranches`, `mergeActor`, or `mergeAuthorization` is absent.

A valid authorization is durable policy data containing:

- authorization ID and authorizer;
- authorization and expiry timestamps;
- exact repository and PR number;
- exact base branch and merge method;
- approval source reference;
- current policy digest;
- optional revocation or supersession metadata.

After an exact-head zero-finding review, the flow enters `merge_ready` with `mergeAuthorized=false`. The owner must invoke the revision-fenced `authorize` action. The controller then revalidates the configured authorization and queues the merge only for the same reviewed head.

Only the merge commit method is supported. The repository broker must return structured evidence that the expected base, head, actor, required checks, review coverage, and synthetic merge commit all match.

## Webhooks

Default routes:

- GitHub: `/plugins/pr-lifecycle-taskflow/github`
- broker events: `/plugins/pr-lifecycle-taskflow/broker`

GitHub requests require `x-hub-signature-256`. Broker requests require `x-broker-signature-256`. Request bodies are size-bounded before JSON parsing.

## Tool actions

The registered tool is `pr_lifecycle_taskflow`.

Owner actions:

- `admit`: create or refresh an exact-head lifecycle.
- `continue`: advance a ready flow.
- `recover`: reconcile bounded recovery state.
- `authorize`: adopt a configured exact authorization after `merge_ready`.

Read and worker actions:

- `status`: inspect sanitized lifecycle state.
- `report`: submit one structured worker result bound to the active claim.

## Validation

From this directory:

```sh
npm run check
npm test
```

The test suite uses synthetic repositories, actors, paths, SHAs, and webhook payloads. It does not require live credentials or network access.
