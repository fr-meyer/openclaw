---
summary: "Use admitted native caller identity in an existing node invocation policy"
read_when:
  - Binding a plugin node action to its actual admitted agent session
---

# Native caller in a node invocation policy

The existing node invocation policy callback can receive a host-owned
`runtimeCaller` when the request has an active admitted agent runtime identity.
It is absent for callers without that identity, including ordinary operator or
device callers. Do not substitute `params.sessionKey`, an environment variable,
a request label, or the client connection ID.

The snapshot contains `agentId`, optional `sessionKey`, and a synchronous
`assertCurrent()`. These fields come from the internal runtime principal already
validated by Gateway admission, not from policy request parameters. No execution
token or delegated-authority secret is exposed.

A principal-sensitive policy must require the snapshot, call its assertion, and
compare the principal with the operation’s independently accepted policy. After
awaited readiness work, assert again before dispatching the exact accepted action
through the existing `invokeNode()` callback. That callback independently rechecks
native runtime authority, approval authority, plugin lifetime and node readiness
before transport. Reading the snapshot is not itself permission to execute.

The object is an in-process policy handle, not a serialized authentication proof.
Do not write it to a file or forward its fields to Python, environment variables
or a remote process as a substitute for native receiving authorization. Keep
operation/action binding in the policy and preserve existing command approvals.

The native assertion also retains private-transport and stream-runtime liveness.
Compose task policy inside the existing command owner. Do not introduce a
competing registration or infer registration ownership from load-path order.

The literal runtimeCaller.supportsDispatchAuthorization advertises enforcement
of invokeNode({ isDispatchAuthorized }). Capture that synchronous host predicate
once before awaiting; the existing final native dispatch gate requires exactly
true and rejects exceptions before standing-grant consumption. No predicate is
serialized to the node. An absent predicate preserves existing policy behavior.
A task wrapper can close its owner lifetime in finally so pending callbacks
cannot dispatch later. This is not caller identity or proof from model inputs.
