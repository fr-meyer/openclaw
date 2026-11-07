#!/usr/bin/env python3
"""Offline admission contracts for the existing fork-release lane; no operations."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess

import release

HEX256 = re.compile(r"[0-9a-f]{64}\Z")
VERSION = re.compile(r"v[0-9]{4}\.[1-9][0-9]*\.(?:0|[1-9][0-9]*)\Z")
DISPOSITIONS = {"upstreamed", "adapt", "carry", "retire", "unknown"}
BOUNDARIES = {"container", "host", "tooling"}
LEGACY_SEED = ("fork-main-seed-20260929", "8b1f5c8ff5d02d45e23d685e67d460c21514c87a")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def utc(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        raise ValueError("expected UTC timestamp")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


class Checks:
    def __init__(self):
        self.errors = []

    def need(self, condition, code):
        if not condition:
            self.errors.append(code)

    def fields(self, value, names, code):
        valid = type(value) is dict and set(value) == set(names.split())
        self.need(valid, code)
        return valid

    def timestamp(self, value, code):
        try:
            return utc(value)
        except ValueError:
            self.errors.append(code)
            return None


def inventory_checks(checks, inventory, manifest, manifest_hash):
    if not checks.fields(inventory, "schema repository candidate manifestSha256 upstream patches", "inventory.fields"):
        return [], []
    checks.need(inventory["schema"] == "openclaw.fork-patch-inventory.v1", "inventory.schema")
    checks.need(inventory["repository"] == manifest["repository"], "inventory.repository")
    checks.need(inventory["candidate"] == manifest["candidate"], "inventory.candidate")
    checks.need(inventory["manifestSha256"] == manifest_hash, "inventory.manifest")
    upstream = inventory["upstream"]
    if upstream is None:
        checks.need(not manifest["productionEligible"] and (manifest["candidate"], manifest["source"]["commit"]) == LEGACY_SEED, "inventory.upstream.required")
    elif checks.fields(upstream, "tag tagObject commit verificationSha256", "inventory.upstream.fields"):
        checks.need(release.matches(VERSION, upstream["tag"]), "inventory.upstream.stable_tag")
        checks.need(release.matches(release.SHA, upstream["tagObject"]), "inventory.upstream.tag_object")
        checks.need(upstream["commit"] == manifest["source"]["baseCommit"], "inventory.upstream.base")
        checks.need(release.matches(HEX256, upstream["verificationSha256"]), "inventory.upstream.verification")
    patches = inventory["patches"]
    if type(patches) is not list or not 1 <= len(patches) <= 128:
        checks.need(False, "inventory.patches.length")
        return [], []
    applied, ids, tests, ledger = [], [], [], []
    for index, entry in enumerate(patches):
        prefix = f"inventory.patch.{index}"
        if not checks.fields(entry, "id originCommit disposition appliedCommit rationale evidenceSha256 regressionTests dependsOn regressionOwner paths", prefix + ".fields"):
            continue
        checks.need(release.matches(release.IDENT, entry["id"]), prefix + ".id")
        ids.append(entry["id"])
        checks.need(type(entry["dependsOn"]) is list and all(dep in ids[:-1] for dep in entry["dependsOn"]), prefix + ".dependencies")
        checks.need(release.matches(release.IDENT, entry["regressionOwner"]), prefix + ".regression_owner")
        checks.need(release.matches(release.SHA, entry["originCommit"]), prefix + ".origin")
        checks.need(type(entry["disposition"]) is str and entry["disposition"] in DISPOSITIONS, prefix + ".disposition")
        checks.need(isinstance(entry["rationale"], str) and bool(entry["rationale"].strip()), prefix + ".rationale")
        checks.need(entry["disposition"] != "unknown", prefix + ".unresolved")
        if entry["disposition"] in ("carry", "adapt"):
            checks.need(release.matches(release.SHA, entry["appliedCommit"]), prefix + ".applied")
            applied.append(entry["appliedCommit"])
        else:
            checks.need(entry["appliedCommit"] is None, prefix + ".not_applied")
            checks.need(release.matches(HEX256, entry["evidenceSha256"]), prefix + ".decision_evidence")
        checks.need(entry["evidenceSha256"] is None or release.matches(HEX256, entry["evidenceSha256"]), prefix + ".evidence")
        paths = entry["paths"]
        if type(paths) is not list or not paths:
            checks.need(False, prefix + ".paths")
        else:
            for path_index, item in enumerate(paths):
                code = prefix + f".path.{path_index}"
                if not checks.fields(item, "path boundary sourceCommit sourceTree sourceBlob upstreamBlob candidateBlob", code + ".fields"):
                    continue
                path = item["path"]
                valid = isinstance(path, str) and bool(re.fullmatch(r"[A-Za-z0-9_./@+-]+", path)) and not path.startswith("/") and not any(part in ("", ".", "..") for part in path.split("/"))
                checks.need(valid, code + ".name")
                checks.need(type(item["boundary"]) is str and item["boundary"] in BOUNDARIES, code + ".boundary")
                for key in ("sourceCommit", "sourceTree", "sourceBlob"):
                    checks.need(release.matches(release.SHA, item[key]), code + "." + key)
                for key in ("upstreamBlob", "candidateBlob"):
                    checks.need(item[key] is None or release.matches(release.SHA, item[key]), code + "." + key)
                if valid and all(release.matches(release.SHA, item[key]) for key in ("sourceCommit", "sourceTree", "sourceBlob")):
                    ledger.append(item)
        refs = entry["regressionTests"]
        if type(refs) is not list or not 1 <= len(refs) <= 24:
            checks.need(False, prefix + ".regressions")
            continue
        for test in refs:
            valid = release.matches(release.TEST_PATH, test) and not test.startswith("/") and ".." not in test.split("/")
            checks.need(valid, prefix + ".regression_path")
            if valid:
                tests.append(test)
    # Compare ordered lists, not sets: an adaptation is the applied commit.
    checks.need(len(ids) == len(set(str(item) for item in ids)), "inventory.duplicate_id")
    checks.need(applied == [p["commit"] for p in manifest["source"]["patches"]], "inventory.ordered_queue")
    return tests, ledger


def source_checks(checks, manifest, source_dir, inventory_tests, ledger, upstream=None, check_head=True, origins=()):
    def git_value(code, *args):
        try:
            return release.git(source_dir, *args)
        except (OSError, subprocess.CalledProcessError):
            checks.need(False, code)
            return None

    try:
        partial = subprocess.run(["git", "-C", str(source_dir), "config", "--get-regexp",
                                  r"^(extensions\.partialclone|remote\..*\.promisor)$"],
                                 capture_output=True, text=True)
    except OSError:
        checks.need(False, "source.config.unavailable")
        return
    if partial.returncode != 1:
        checks.need(False, "source.partial_clone.unsupported" if partial.returncode == 0 else "source.config.unavailable")
        return
    source = manifest["source"]
    for index, origin in enumerate(origins):
        checks.need(git_value(f"inventory.origin.{index}.object", "cat-file", "-t", origin) == "commit", f"inventory.origin.{index}.commit")
    if type(upstream) is dict and release.matches(release.SHA, upstream.get("tagObject")):
        tag = git_value("upstream.tag.unavailable", "cat-file", "tag", upstream["tagObject"])
        if tag is not None:
            header = dict(line.split(" ", 1) for line in tag.split("\n\n", 1)[0].splitlines() if " " in line)
            checks.need(header.get("object") == source["baseCommit"] and header.get("type") == "commit" and header.get("tag") == upstream.get("tag"), "upstream.tag.binding")
    if check_head:
        checks.need(git_value("source.checkout.unavailable", "rev-parse", "HEAD") == source["commit"], "source.checkout")
    try:
        release.check_source_graph(source, source_dir)
    except (OSError, subprocess.CalledProcessError, release.Refusal, ValueError, KeyError, TypeError):
        checks.need(False, "source.graph.refused")
    tests = inventory_tests + [test for lane in manifest["gates"].values() for test in lane]
    changed = git_value("source.coverage.unavailable", "diff", "--name-only", "--no-renames", source["baseCommit"], source["commit"])
    if changed is not None and ledger is not None:
        checks.need(set(changed.splitlines()) <= {item["path"] for item in ledger}, "inventory.coverage.missing")
    for index, item in enumerate(ledger or []):
        code = f"inventory.path.{index}"
        checks.need(git_value(code + ".source_object", "rev-parse", f"{item['sourceCommit']}^{{tree}}") == item["sourceTree"], code + ".source_tree")
        checks.need(git_value(code + ".source_path", "rev-parse", f"{item['sourceCommit']}:{item['path']}") == item["sourceBlob"], code + ".source_blob")
        for commit, key in ((source["baseCommit"], "upstreamBlob"), (source["commit"], "candidateBlob")):
            # Absence is a deliberate ledger value; inspect the tree rather than treating a failed command as absence.
            observed = git_value(code + "." + key + ".object", "ls-tree", commit, "--", item["path"])
            if observed is not None:
                blob = observed.split()[2] if observed else None
                checks.need(blob == item[key], code + "." + key)
    for index, test in enumerate(dict.fromkeys(tests)):
        git_value(f"source.test.{index}.missing", "cat-file", "-e", f"{source['commit']}:{test}")





def origin_commits(inventory):
    patches = inventory.get("patches") if type(inventory) is dict else None
    return [entry["originCommit"] for entry in (patches if type(patches) is list else [])
            if type(entry) is dict and release.matches(release.SHA, entry.get("originCommit"))]

def history_commits(inventory, manifest=None):
    """Exact fork objects needed to verify historical origin/path identities."""
    identities = {entry["originCommit"] for entry in inventory["patches"]} | {
        item["sourceCommit"] for entry in inventory["patches"] for item in entry["paths"]}
    if manifest is not None and "merge" in manifest["source"]:
        source = manifest["source"]
        identities.update((source["baseCommit"], source["commit"],
                           source["merge"]["forkCommit"], source["merge"]["commonCommit"]))
        if source["merge"].get("schema") == "openclaw.fork-source-merge.v3":
            merge = source["merge"]
            identities.update(item["commit"] for item in
                              [merge["integration"], merge["securitySource"], *merge["successors"]])
    return sorted(identities)

def inventory_at(path, manifest, manifest_hash, source_dir=None, check_head=True):
    """Fail closed on the reviewed ledger; optional local Git checks never fetch."""
    checks = Checks()
    try:
        inventory = release.read_json(path)
        tests, ledger = inventory_checks(checks, inventory, manifest, manifest_hash)
    except (OSError, ValueError, TypeError, KeyError):
        raise release.Refusal("inventory.invalid")
    if source_dir is not None:
        source_checks(checks, manifest, source_dir, tests, ledger,
                      inventory.get("upstream") if type(inventory) is dict else None, check_head,
                      origin_commits(inventory))
    release.need(not checks.errors, "preflight: " + ", ".join(sorted(set(checks.errors))))
    return inventory, digest(path)

def backup_checks(checks, evidence, baseline, image_digest, now, max_age, retain_for):
    """Validate private observations; an adapter must independently establish facts."""
    if not checks.fields(evidence, "schema baseline archive restore", "backup.fields"):
        return
    checks.need(evidence["schema"] == "openclaw.fork-backup-evidence.v1", "backup.schema")
    checks.need(checks.fields(baseline, "sourceSha imageDigest mutableInventorySha256", "baseline.fields"), "backup.baseline.required")
    if type(baseline) is dict:
        checks.need(release.matches(release.SHA, baseline.get("sourceSha")), "baseline.source")
        checks.need(release.matches(release.DIGEST, baseline.get("imageDigest")), "baseline.image")
        checks.need(release.matches(HEX256, baseline.get("mutableInventorySha256")), "baseline.mutable_inventory")
    checks.need(evidence["baseline"] == baseline, "backup.baseline.changed")
    checks.need(type(max_age) is int and max_age > 0, "backup.policy.max_age")
    checks.need(type(retain_for) is int and retain_for > 0, "backup.policy.retention")
    archive = evidence["archive"]
    if checks.fields(archive, "receiptId sha256 sizeBytes exists capturedAt verifiedAt retainUntil", "backup.archive.fields"):
        checks.need(release.matches(release.IDENT, archive["receiptId"]), "backup.archive.receipt")
        checks.need(release.matches(HEX256, archive["sha256"]), "backup.archive.digest")
        checks.need(type(archive["sizeBytes"]) is int and archive["sizeBytes"] > 0, "backup.archive.empty")
        checks.need(archive["exists"] is True, "backup.archive.absent")
        captured = checks.timestamp(archive["capturedAt"], "backup.archive.captured_at")
        verified = checks.timestamp(archive["verifiedAt"], "backup.archive.verified_at")
        retained = checks.timestamp(archive["retainUntil"], "backup.archive.retain_until")
        if captured and verified:
            checks.need(captured <= verified <= now, "backup.archive.time_order")
            if type(max_age) is int and max_age > 0:
                checks.need(0 <= (now - captured).total_seconds() <= max_age, "backup.archive.stale")
                checks.need(0 <= (now - verified).total_seconds() <= max_age, "backup.archive.verification_stale")
        if retained and type(retain_for) is int and retain_for > 0:
            checks.need((retained - now).total_seconds() >= retain_for, "backup.archive.retention_short")
    restored = evidence["restore"]
    if checks.fields(restored, "receiptId archiveSha256 imageDigest state", "backup.restore.fields"):
        checks.need(release.matches(release.IDENT, restored["receiptId"]), "backup.restore.receipt")
        checks.need(type(archive) is dict and restored["archiveSha256"] == archive.get("sha256"), "backup.restore.archive")
        checks.need(restored["imageDigest"] == image_digest and release.matches(release.DIGEST, image_digest), "backup.restore.image")
        checks.need(restored["state"] == "passed", "backup.restore.unproved")


def deployment_checks(checks, receipt, manifest, manifest_hash, inventory_hash, image, image_hash, upstream_tag):
    names = ("schema repository version deploymentId deploymentTag deployedAt sourceSha sourceTree "
             "manifestSha256 inventorySha256 imageReceiptSha256 indexDigest imageDigest configDigest "
             "toolingSha producer privateEvidenceSha256 rollbackDeploymentTag phaseStates")
    if not checks.fields(receipt, names, "deployment.fields"):
        return
    checks.need(receipt["schema"] == "openclaw.fork-deployment.v1", "deployment.schema")
    checks.need(release.matches(VERSION, receipt["version"]), "deployment.version")
    checks.need(isinstance(image.get("version"), str) and receipt["version"] == "v" + image["version"], "deployment.version.image")
    checks.need(receipt["version"] == upstream_tag and release.matches(VERSION, upstream_tag), "deployment.version.upstream")
    for owner, producer in (("deployment", receipt["producer"]), ("image", image["producer"])):
        if checks.fields(producer, release.producer_fields(producer), owner + ".producer.fields"):
            try:
                release.validate_producer(producer)
            except release.Refusal:
                checks.need(False, owner + ".producer.invalid")
    checks.need(release.matches(re.compile(r"[0-9a-f]{32}\Z"), receipt["deploymentId"]), "deployment.id")
    deployed = checks.timestamp(receipt["deployedAt"], "deployment.time")
    if deployed:
        tag = f"deploy/{receipt['version']}/{deployed.strftime('%Y%m%dT%H%M%SZ')}-{receipt['deploymentId']}"
        checks.need(receipt["deploymentTag"] == tag, "deployment.tag")
    expected = {"repository": manifest["repository"], "sourceSha": manifest["source"]["commit"],
                "sourceTree": manifest["source"]["tree"], "manifestSha256": manifest_hash,
                "inventorySha256": inventory_hash, "imageReceiptSha256": image_hash,
                **{key: image[key] for key in ("indexDigest", "imageDigest", "configDigest", "producer")}}
    for key, value in expected.items():
        checks.need(receipt[key] == value, "deployment.binding." + key)
    checks.need(release.matches(release.SHA, receipt["toolingSha"]), "deployment.tooling")
    checks.need(release.matches(HEX256, receipt["privateEvidenceSha256"]), "deployment.private_evidence")
    tag_pattern = re.compile(r"deploy/v[0-9]{4}\.[1-9][0-9]*\.[0-9]+(?:-beta\.[1-9][0-9]*)?/[0-9]{8}T[0-9]{6}Z-[0-9a-f]{32}\Z")
    checks.need(release.matches(tag_pattern, receipt["rollbackDeploymentTag"]), "deployment.rollback_tag")
    phases = receipt["phaseStates"]
    if checks.fields(phases, "backup restore rehearsal deploy health rollback cleanup", "deployment.phases"):
        for phase in ("backup", "restore", "rehearsal", "deploy", "health"):
            checks.need(phases[phase] == "passed", "deployment.phase." + phase)
        checks.need(phases["rollback"] == "not_run", "deployment.phase.rollback")
        checks.need(phases["cleanup"] in ("passed", "not_run"), "deployment.phase.cleanup")
    checks.need(manifest["productionEligible"], "deployment.seed_ineligible")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("manifest", "inventory"):
        parser.add_argument("--" + option, required=True, type=Path)
    parser.add_argument("--source-dir", type=Path)
    parser.add_argument("--metadata-only", action="store_true")
    for option in ("image-receipt", "backup-evidence", "baseline", "deployment-receipt"):
        parser.add_argument("--" + option, type=Path)
    parser.add_argument("--now", type=utc, default=datetime.now(timezone.utc))
    parser.add_argument("--backup-max-age-seconds", type=int)
    parser.add_argument("--backup-retain-seconds", type=int)
    args = parser.parse_args()
    checks = Checks()

    def read(path, label):
        try:
            value = release.read_json(path)
            if type(value) is not dict:
                checks.need(False, label + ".object")
                return None
            return value
        except (OSError, ValueError, TypeError):
            checks.need(False, label + ".unreadable")
            return None

    try:
        manifest, manifest_hash = release.manifest_at(args.manifest)
    except (OSError, ValueError, release.Refusal, KeyError, TypeError):
        manifest, manifest_hash = None, None
        checks.need(False, "manifest.invalid")
    inventory = read(args.inventory, "inventory")
    if manifest is not None:
        tests, ledger, upstream = [], None, None
        if inventory is not None:
            tests, ledger = inventory_checks(checks, inventory, manifest, manifest_hash)
            upstream = inventory.get("upstream")
        if not args.metadata_only:
            if args.source_dir is None:
                checks.need(False, "source.checkout.required")
            else:
                source_checks(checks, manifest, args.source_dir, tests, ledger, upstream, origins=origin_commits(inventory))
        if not checks.errors and not args.metadata_only:
            try:
                release.check_source(manifest, args.source_dir)
            except (OSError, subprocess.CalledProcessError, release.Refusal):
                checks.need(False, 'source.canonical.refused')
    image = None
    if args.image_receipt and manifest is not None:
        try:
            image = release.receipt_at(args.image_receipt, manifest, manifest_hash, digest(args.inventory))
        except (OSError, ValueError, release.Refusal, KeyError, TypeError):
            checks.need(False, "image_receipt.invalid")
    if args.backup_evidence:
        backup = read(args.backup_evidence, "backup")
        baseline = read(args.baseline, "baseline")
        if backup is not None:
            backup_checks(checks, backup, baseline, image["indexDigest"] if image else None,
                          args.now, args.backup_max_age_seconds, args.backup_retain_seconds)
    if args.deployment_receipt:
        receipt = read(args.deployment_receipt, "deployment")
        checks.need(image is not None, "deployment.image_receipt.required")
        if receipt is not None and manifest is not None and image is not None and inventory is not None:
            deployment_checks(checks, receipt, manifest, manifest_hash, digest(args.inventory),
                              image, digest(args.image_receipt),
                              inventory["upstream"].get("tag") if type(inventory.get("upstream")) is dict else None)
    errors = sorted(set(checks.errors))
    print(json.dumps({"schema": "openclaw.fork-preflight.v1", "passed": not errors, "errors": errors,
                      "deploymentAuthorized": False}, indent=2))
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
