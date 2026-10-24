#!/usr/bin/env python3
"""Acquire bounded merge ancestry in an existing ordinary candidate checkout."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

import preflight
import release


FORK_URL = "https://github.com/fr-meyer/openclaw.git"
FETCH_DEPTH = 512
FETCH_TIMEOUT_SECONDS = 180


def git_environment():
    return {**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0"}


def ordinary_checkout(source_dir):
    release.need(release.git(source_dir, "rev-parse", "--is-bare-repository") == "false",
                 "ancestry.checkout.bare")
    config = subprocess.run(
        ["git", "--no-replace-objects", "-C", str(source_dir), "config", "--get-regexp",
         r"^(extensions\.partialclone|remote\..*\.promisor)$"],
        capture_output=True, text=True, env=git_environment(), timeout=15,
    )
    release.need(config.returncode == 1,
                 "ancestry.partial_clone.unsupported" if config.returncode == 0 else "ancestry.config.unavailable")


def head_commit(source_dir):
    head = release.git(source_dir, "rev-parse", "--verify", "HEAD^{commit}")
    release.need(release.matches(release.SHA, head), "ancestry.checkout.head")
    return head


def fetch_source(source_dir, source_sha):
    """One explicit fixed-origin fetch; never retry or fall back to full history."""
    release.need(release.matches(release.SHA, source_sha), "ancestry.source.invalid")
    subprocess.run(
        ["git", "--no-replace-objects", "-C", str(source_dir), "fetch", "--no-tags",
         f"--depth={FETCH_DEPTH}", "--no-recurse-submodules", "--no-auto-maintenance",
         FORK_URL, source_sha],
        capture_output=True, text=True, check=True, timeout=FETCH_TIMEOUT_SECONDS,
        env=git_environment(),
    )


def acquire(manifest_path, inventory_path, source_dir):
    """Acquire objects only; existing source/PR owners retain checkout/seal policy."""
    manifest, manifest_hash = release.manifest_at(manifest_path)
    _, inventory_hash = preflight.inventory_at(inventory_path, manifest, manifest_hash)
    ordinary_checkout(source_dir)
    before = head_commit(source_dir)
    source = manifest["source"]
    result = {
        "schema": "openclaw.fork-source-ancestry.v1", "sourceSha": source["commit"],
        "headSha": before, "manifestSha256": manifest_hash, "inventorySha256": inventory_hash,
        "fetched": False, "fetchDepth": None, "status": "not_required_linear",
    }
    if "merge" not in source:
        return result
    try:
        try:
            fetch_source(source_dir, source["commit"])
        except subprocess.TimeoutExpired as error:
            raise release.Refusal("ancestry.fetch.timeout") from error
        except (OSError, subprocess.CalledProcessError) as error:
            raise release.Refusal("ancestry.fetch.failed") from error
    finally:
        release.need(head_commit(source_dir) == before, "ancestry.checkout.head_changed")
    release.need(preflight.digest(manifest_path) == manifest_hash
                 and preflight.digest(inventory_path) == inventory_hash, "ancestry.metadata.changed")
    try:
        release.check_source_graph(source, source_dir)
    except (OSError, subprocess.CalledProcessError) as error:
        raise release.Refusal("ancestry.graph.unavailable") from error
    result.update(fetched=True, fetchDepth=FETCH_DEPTH, status="verified")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--source-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = acquire(args.manifest, args.inventory, args.source_dir)
    except release.Refusal as error:
        print(json.dumps({"schema": "openclaw.fork-source-ancestry.v1", "status": "refused", "error": str(error)}))
        return 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print(json.dumps({"schema": "openclaw.fork-source-ancestry.v1", "status": "refused", "error": "ancestry.input.invalid"}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
