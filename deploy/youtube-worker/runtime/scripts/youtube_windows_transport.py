"""Audited node command transport; scheduling and lease ownership stay in GCP."""
from __future__ import annotations
import json
import subprocess
from pathlib import Path
from typing import Any
from youtube_safe_diagnostics import parse_json_record
WORKSPACE = Path(__file__).resolve().parents[1]
UNSAFE_NOTIFICATION_MARKERS = ("base64", "stdout:", "stderr:", "scripts/openclaw-node-run", "python3 -c", "\x1b")


class SupervisorOperationError(RuntimeError):
    """A supervisor failure whose text is safe to persist and notify."""


class NodeUnavailable(SupervisorOperationError):
    def __init__(self, node: str, reason: str) -> None:
        self.node = node
        self.reason = reason
        super().__init__(
            f"node {node!r} is {reason}; no remote command was started. "
            "Automatic retry will occur at the next supervisor check."
        )


class NodeRequestTimedOut(SupervisorOperationError):
    def __init__(self, operation: str) -> None:
        super().__init__(
            f"{operation} timed out; the supervisor will re-check the node "
            "before taking further remote action."
        )


class SafeCommandFailure(SupervisorOperationError):
    def __init__(self, operation: str, returncode: int) -> None:
        self.operation = operation
        self.returncode = returncode
        super().__init__(
            f"{operation} failed (exit {returncode}); no further supervisor action was taken."
        )


def safe_message(value: Any, fallback: str) -> str:
    """Return concise text that cannot expose a generated command or terminal dump."""
    text = " ".join(str(value).split())
    lowered = text.lower()
    if not text or len(text) > 280 or any(marker in lowered for marker in UNSAFE_NOTIFICATION_MARKERS):
        return fallback
    return text


def configured_node_name(config: dict[str, Any]) -> str:
    return safe_message(config.get("node") or "configured node", "configured node")


def run_command(
    argv: list[str],
    *,
    timeout: int = 1800,
    check: bool = True,
    operation: str = "supervisor command",
    node_name: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run an internal command without ever returning raw argv/stdout/stderr in an error."""
    try:
        completed = subprocess.run(
            argv,
            cwd=WORKSPACE,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise NodeRequestTimedOut(operation) from None
    if check and completed.returncode != 0:
        diagnostic = f"{completed.stdout or ''}\n{completed.stderr or ''}".lower()
        label = node_name or "configured node"
        if "node is not connected" in diagnostic or "node disconnected" in diagnostic:
            raise NodeUnavailable(label, "disconnected")
        if "node not found" in diagnostic:
            raise NodeUnavailable(label, "not paired or visible")
        if "does not advertise system.run" in diagnostic:
            raise NodeUnavailable(label, "not available for remote execution")
        if "node invoke timed out" in diagnostic or "node request timed out" in diagnostic:
            raise NodeRequestTimedOut(operation)
        raise SafeCommandFailure(operation, completed.returncode)
    return completed


def parse_json_output(text: str) -> Any:
    return parse_json_record(text, allow_prefix=True)


def require_connected_node(config: dict[str, Any]) -> dict[str, Any]:
    """Verify the configured node can run commands before generating any payload."""
    node_name = configured_node_name(config)
    status = run_command(
        ["openclaw", "nodes", "status", "--json", "--timeout", "30000"],
        timeout=45,
        operation="node connectivity preflight",
        node_name=node_name,
    )
    try:
        payload = parse_json_output(status.stdout)
    except Exception as exc:
        raise NodeUnavailable(node_name, "status could not be read") from None
    nodes = payload.get("nodes") if isinstance(payload, dict) else None
    if not isinstance(nodes, list):
        raise NodeUnavailable(node_name, "status is unavailable")
    needle = node_name.casefold()
    matches = [
        node for node in nodes
        if isinstance(node, dict)
        and any(str(value).casefold() == needle for value in (node.get("nodeId"), node.get("displayName"), node.get("remoteIp")) if value)
    ]
    if not matches:
        raise NodeUnavailable(node_name, "not paired or visible")
    node = next((entry for entry in matches if entry.get("connected") is True), matches[0])
    if node.get("connected") is not True:
        raise NodeUnavailable(node_name, "disconnected")
    commands = node.get("commands")
    if not isinstance(commands, list) or "system.run" not in commands:
        raise NodeUnavailable(node_name, "not available for remote execution")
    return node


def run_node_command(
    config: dict[str, Any], command: list[str], *, timeout: int, operation: str, preflight: bool = True
) -> subprocess.CompletedProcess[str]:
    node_name = configured_node_name(config)
    if preflight:
        require_connected_node(config)
    argv = ["scripts/youtube_worker/openclaw-node-run", "--node", str(config["node"]), "--agent", str(config["agent_id"]), "--timeout-ms", str(timeout * 1000)]
    node_cwd = str(config.get("node_cwd") or "").strip()
    if node_cwd:
        argv.extend(["--cwd", node_cwd])
    argv.extend(["--", *command])
    return run_command(
        argv,
        timeout=timeout,
        operation=operation,
        node_name=node_name,
    )
