#!/usr/bin/env python3
"""Existing-VM daily-snapshot rehearsal lifecycle. No production activation.

Cloud/host changes require an exact action challenge. Merely preparing or
observing a run does not dispatch them. An interrupted request is reconciled,
never resubmitted. Native checks stay with gcp_snapshot_trial's sole supervisor.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid

import gcp_build as durable
import gcp_rehearsal as contracts
import gcp_snapshot_trial as trial
from gcp_snapshot_cloud import Cloud, inspect_operation, operation_receipt, select_snapshot, timestamp
import release

ROOT = Path('/var/tmp/openclaw-fork-daily-rehearsal')
MOUNTS = Path('/mnt/openclaw-daily-rehearsal')
NAME = re.compile(r'[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
PROJECT = re.compile(r'[a-z][a-z0-9-]{4,61}[a-z0-9]\Z')
ID = re.compile(r'[1-9][0-9]{0,19}\Z')
HEX = re.compile(r'[0-9a-f]{64}\Z')
GENERATIONS = ('candidate', 'rollback')
VERBS = ('restore', 'attach', 'mount', 'unmount', 'detach', 'delete')
HELPERS = ('gcp_daily_snapshot.py', 'gcp_snapshot_cloud.py', 'gcp_rehearsal.py',
           'gcp_rehearsal_checks.py', *trial.HELPERS)
HELPERS = tuple(dict.fromkeys(HELPERS))
need = release.need


class HostFailure(release.Refusal):
    """The native host command returned a nonzero exit and has been joined."""


def hash_bytes(value):
    return hashlib.sha256(value).hexdigest()


def now():
    return datetime.now(timezone.utc)


def canonical_link(value):
    need(type(value) is str, 'daily.link.type')
    for prefix in ('https://www.googleapis.com/compute/v1/', 'https://compute.googleapis.com/compute/v1/'):
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    need(re.fullmatch(r'projects/[a-z][a-z0-9-]+/(?:zones/[a-z0-9-]+/(?:instances|disks)|global/snapshots|regions/[a-z0-9-]+/resourcePolicies)/[a-z][a-z0-9-]*', value), 'daily.link.invalid')
    return value


def link(plan, kind, name):
    return f"projects/{plan['project']}/zones/{plan['zone']}/{kind}/{name}"


def snapshot_link(plan, name):
    return f"projects/{plan['project']}/global/snapshots/{name}"


def fields(value, names, code):
    durable.fields(value, names, code)


def validate_plan(plan):
    fields(plan, 'schema operationId toolingSha createdAt expiresAt project zone instance sourceDisk snapshotPolicy baselineImage maxSnapshotAgeSeconds resources', 'daily.plan.fields')
    need(plan['schema'] == 'openclaw.gcp-daily-snapshot.v1' and trial.OP.fullmatch(plan['operationId']) and trial.SHA.fullmatch(plan['toolingSha']), 'daily.plan.identity')
    need(PROJECT.fullmatch(plan['project']) and NAME.fullmatch(plan['zone']), 'daily.plan.location')
    created, expires = contracts.utc(plan['createdAt']), contracts.utc(plan['expiresAt'])
    need(0 < (expires - created).total_seconds() <= 86400, 'daily.plan.ttl')
    for key in ('instance', 'sourceDisk'):
        fields(plan[key], 'name id', 'daily.production.fields')
        need(NAME.fullmatch(plan[key]['name']) and ID.fullmatch(plan[key]['id']), 'daily.production.identity')
    policy = canonical_link(plan['snapshotPolicy'])
    need(policy.startswith(f"projects/{plan['project']}/regions/") and '/resourcePolicies/' in policy, 'daily.snapshot.policy')
    need(type(plan['maxSnapshotAgeSeconds']) is int and 0 < plan['maxSnapshotAgeSeconds'] <= 172800, 'daily.snapshot.age')
    baseline = plan['baselineImage']
    fields(baseline, 'sourceSha version indexDigest imageDigest configDigest gatewayProbeContract', 'daily.baseline.fields')
    need(trial.SHA.fullmatch(baseline['sourceSha']) and re.fullmatch(r'2026\.[0-9]+\.[0-9]+', baseline['version']) and
         all(trial.DIGEST.fullmatch(baseline[k]) for k in ('indexDigest', 'imageDigest', 'configDigest')) and
         baseline['gatewayProbeContract'] in ('healthz-readyz-v1', 'healthz-startupz-readyz-v1'), 'daily.baseline.identity')
    r = plan['resources']
    fields(r, 'diskType maxDiskGiB estimatedCostMicrousd approvedCostMicrousd memoryBytes cpus readBps writeBps minMemoryAvailableBytes minRootFreeBytes minDataFreeBytes timeoutSeconds', 'daily.resources.fields')
    need(r['diskType'] in ('pd-standard', 'pd-balanced') and all(type(v) is int and v > 0 for k, v in r.items() if k != 'diskType'), 'daily.resources.values')
    need(r['maxDiskGiB'] <= 1024 and r['estimatedCostMicrousd'] <= r['approvedCostMicrousd'] <= 1_000_000_000, 'daily.resources.cost')
    trial.resource_profile(r)
    need(trial.memory_admission(r) and 960 <= r['timeoutSeconds'] <= 86400, 'daily.resources.native')


def disk_name(run, generation):
    need(generation in GENERATIONS, 'daily.generation')
    return f"oc-rehearsal-{run['plan']['operationId']}-{generation}"


def api_get(cloud, path, missing=False):
    return cloud.request('GET', path, allow_missing=missing)


def observe_production(cloud, plan, retained=None):
    vm = api_get(cloud, link(plan, 'instances', plan['instance']['name']))
    need(str(vm.get('id')) == plan['instance']['id'] and vm.get('status') == 'RUNNING', 'daily.production.changed_or_stopped')
    disks = vm.get('disks', [])
    need(type(disks) is list and 0 < len(disks) <= 64, 'daily.production.disks')
    source = api_get(cloud, link(plan, 'disks', plan['sourceDisk']['name']))
    need(str(source.get('id')) == plan['sourceDisk']['id'] and source.get('status') == 'READY', 'daily.production.source_changed')
    source_path = link(plan, 'disks', plan['sourceDisk']['name'])
    need(any(canonical_link(d.get('source')) == source_path for d in disks), 'daily.production.source_not_attached')
    protected = []
    for attachment in disks:
        source_ref = canonical_link(attachment['source'])
        if retained and source_ref not in {d['source'] for d in retained['protectedDisks']}:
            continue
        observed = source if source_ref == source_path else api_get(cloud, source_ref)
        need(ID.fullmatch(str(observed.get('id', ''))), 'daily.production.disk_id')
        protected.append({'source': source_ref, 'id': str(observed['id']), 'boot': attachment.get('boot', False),
                          'deviceName': attachment['deviceName'], 'mode': attachment['mode'], 'autoDelete': attachment.get('autoDelete', False)})
    result = {'instanceId': str(vm['id']), 'instanceLink': link(plan, 'instances', plan['instance']['name']),
              'protectedDisks': sorted(protected, key=lambda d: d['source'])}
    if retained:
        need(result == retained, 'daily.production.attachment_changed')
    return vm, source, result


def snapshots(cloud, plan):
    result, token = [], None
    for _ in range(20):
        query = {'maxResults': 500, 'filter': f"sourceDiskId = {plan['sourceDisk']['id']}"}
        if token:
            query['pageToken'] = token
        page = cloud.request('GET', f"projects/{plan['project']}/global/snapshots", query=query)
        result.extend(page.get('items', []))
        token = page.get('nextPageToken')
        if not token:
            return result
    raise release.Refusal('daily.snapshots.page_limit')


def helper_hashes():
    here = Path(__file__).resolve().parent
    return {name: hash_bytes((here / name).read_bytes()) for name in HELPERS}


LOADED_HELPERS = helper_hashes()


def daily_snapshot(cloud, plan, source):
    policy = api_get(cloud, canonical_link(plan['snapshotPolicy']))
    need(ID.fullmatch(str(policy.get('id', ''))) and
         canonical_link(policy.get('selfLink')) == canonical_link(plan['snapshotPolicy']) and
         policy.get('snapshotSchedulePolicy', {}).get('schedule', {}).get('dailySchedule', {}).get('daysInCycle') == 1,
         'daily.snapshot.not_daily_policy')
    selected = select_snapshot(snapshots(cloud, plan), source, plan['snapshotPolicy'], now(), plan['maxSnapshotAgeSeconds'])
    need(str(selected.get('sourceSnapshotSchedulePolicyId')) == str(policy['id']), 'daily.snapshot.policy_incarnation')
    return selected


def prepare(plan_path, image_path, tooling, cloud):
    plan = json.loads(durable.private_bytes(plan_path))
    image_raw = durable.private_bytes(image_path)
    image = json.loads(image_raw)
    validate_plan(plan)
    need(contracts.utc(plan['createdAt']) <= now() < contracts.utc(plan['expiresAt']), 'daily.plan.expired_or_future')
    trial.qualified_image(image)
    tooling = Path(tooling).resolve()
    durable.clean_checkout(tooling, plan['toolingSha'])
    files = {name: subprocess.check_output(['git', '-C', str(tooling), 'show', f"{plan['toolingSha']}:scripts/fork-release/{name}"]) for name in HELPERS}
    need(LOADED_HELPERS == helper_hashes() == {name: hash_bytes(raw) for name, raw in files.items()}, 'daily.running_tooling.changed')
    root = release.private_root(ROOT)
    op = root / plan['operationId']
    if op.exists():
        _, previous = load(op)
        need(previous['plan'] == plan and previous['imageReceiptSha256'] == hash_bytes(image_raw), 'daily.prepare.existing_conflict')
        return op
    _, source, protected = observe_production(cloud, plan)
    chosen = daily_snapshot(cloud, plan, source)
    need(int(chosen['diskSizeGb']) <= plan['resources']['maxDiskGiB'], 'daily.snapshot.capacity')
    op.mkdir(mode=0o700)
    (op / 'tooling').mkdir(mode=0o700)
    for name, raw in files.items():
        durable.write_once(op / 'tooling' / name, raw)
    run = {'schema': 'openclaw.gcp-daily-run.v1', 'plan': plan, 'image': image,
           'imageReceiptSha256': hash_bytes(image_raw), 'snapshot': chosen, 'production': protected,
           'ownerUid': os.getuid(), 'ownerGid': os.getgid(), 'helpers': helper_hashes(), 'preparedAt': durable.now()}
    durable.write_once(op / 'image-receipt.json', image_raw)
    durable.write_once(op / 'run.json', durable.encode(run))
    return op


def load(op):
    op = Path(op).absolute()
    need(op.resolve() == op and op.parent == ROOT.resolve(), 'daily.operation.path')
    info = op.stat()
    need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'daily.operation.owner')
    run = durable.read_private(op / 'run.json')
    validate_plan(run['plan'])
    need(run['plan']['operationId'] == op.name and run['ownerUid'] == os.getuid() and run['ownerGid'] == os.getgid(), 'daily.operation.identity')
    need(LOADED_HELPERS == helper_hashes() == run['helpers'] and all(hash_bytes(durable.private_bytes(op / 'tooling' / name)) == hashed for name, hashed in run['helpers'].items()), 'daily.tooling.changed')
    need(hash_bytes(durable.private_bytes(op / 'image-receipt.json')) == run['imageReceiptSha256'], 'daily.image.changed')
    return op, run


def record(op, name, value):
    key, separator, tail = name.partition('.')
    keys = {verb + '-' + generation for verb in VERBS for generation in GENERATIONS}
    destination = action_file(op, key, tail[:-5]) if separator and key in keys and tail.endswith('.json') else op / name
    durable.write_once(destination, durable.encode(value))


def retain(path, raw):
    """Resume immutable staging after a crash without replacing prior evidence."""
    if path.exists():
        need(durable.private_bytes(path) == raw, 'daily.retained.conflict')
    else:
        durable.write_once(path, raw)


def action_key(verb, generation):
    need(verb in VERBS and generation in GENERATIONS, 'daily.action.invalid')
    return verb + '-' + generation


def action_file(op, key, suffix):
    pointer = op / ('attempt-current-' + key + '.json')
    if not pointer.exists():
        return op / (key + '.' + suffix + '.json')
    current = durable.read_private(pointer)
    need(type(current.get('attempt')) is int and 2 <= current['attempt'] <= 8 and
         HEX.fullmatch(current.get('previousFailureSha256', '')), 'daily.retry.pointer')
    return op / (key + '-attempt-' + str(current['attempt'])) / (key + '.' + suffix + '.json')


def attempt_binding(op, key):
    pointer = op / ('attempt-current-' + key + '.json')
    if not pointer.exists():
        return {'attempt': 1}
    current = durable.read_private(pointer)
    # Reuse action_file's strict pointer validation, then bind its immutable
    # preparation record so a partial pointer cannot manufacture a new attempt.
    directory = action_file(op, key, 'intent').parent
    need(durable.read_private(directory / 'retry-parent.json') == current, 'daily.retry.parent_changed')
    previous = op if current['attempt'] == 2 else op / (key + '-attempt-' + str(current['attempt'] - 1))
    result_file = previous / (key + '.result.json')
    result = durable.read_private(result_file)
    need(hash_bytes(durable.private_bytes(result_file)) == current['previousFailureSha256'] and
         result['state'] == 'failed' and result['intentSha256'] ==
         hash_bytes(durable.private_bytes(previous / (key + '.intent.json'))), 'daily.retry.previous_changed')
    return current


def completed(op, key):
    file = action_file(op, key, 'result')
    if not file.exists():
        return None
    value = durable.read_private(file)
    need(value['state'] == 'succeeded', 'daily.prerequisite.failed')
    need(value['intentSha256'] == hash_bytes(durable.private_bytes(action_file(op, key, 'intent'))), 'daily.prerequisite.binding')
    return value


def failed_action(op, key):
    file = action_file(op, key, 'result')
    if not file.exists():
        return False
    value = durable.read_private(file)
    need(value['intentSha256'] == hash_bytes(durable.private_bytes(action_file(op, key, 'intent'))), 'daily.prerequisite.binding')
    return value['state'] == 'failed'


def owned_disk(cloud, op, run, generation):
    plan, name = run['plan'], disk_name(run, generation)
    created = completed(op, 'restore-' + generation)
    need(created is not None, 'daily.disk.no_creation_receipt')
    expected = created['resource']
    disk = api_get(cloud, link(plan, 'disks', name))
    need(str(disk.get('id')) == expected['id'] and canonical_link(disk.get('selfLink')) == expected['selfLink'] and
         str(disk.get('sourceSnapshotId')) == str(run['snapshot']['id']) and
         canonical_link(disk.get('sourceSnapshot')) == canonical_link(run['snapshot']['selfLink']), 'daily.disk.incarnation_changed')
    need(not any(expected['id'] == d['id'] or expected['selfLink'] == d['source'] for d in run['production']['protectedDisks']), 'daily.disk.production')
    need(disk.get('labels', {}).get('openclaw-run') == op.name and disk.get('labels', {}).get('openclaw-role') == generation, 'daily.disk.labels_changed')
    return disk


def mount_root(op, generation):
    return MOUNTS / op.name / generation


def host(args, timeout=30):
    result = subprocess.run(args, capture_output=True, timeout=timeout, env=durable.SAFE_ENV)
    if result.returncode != 0:
        raise HostFailure('daily.host.nonzero_exit')
    need(len(result.stdout) <= 1024 * 1024 and len(result.stderr) <= 65536, 'daily.host.output_limit')
    return result.stdout


def mounted():
    value = json.loads(host(['findmnt', '--json', '--list', '--output', 'SOURCE,TARGET,MAJ:MIN']))
    need(len(value.get('filesystems', [])) <= 512, 'daily.mounts.limit')
    return value.get('filesystems', [])


def no_container_users(root):
    ids = trial.docker(['ps', '--quiet', '--no-trunc']).decode().split()
    need(len(ids) <= 64, 'daily.containers.limit')
    if ids:
        for row in trial.docker(['inspect', '--format', '{{json .Mounts}}', *ids]).decode().splitlines():
            for mount in json.loads(row):
                source = mount.get('Source')
                need(not source or not trial.overlaps(root, Path(source).resolve()), 'daily.disk.active_container')


def attachment(vm, disk_ref):
    rows = [d for d in vm.get('disks', []) if canonical_link(d['source']) == disk_ref]
    need(len(rows) <= 1, 'daily.disk.duplicate_attachment')
    return rows[0] if rows else None


def open_generation(op, generation):
    need(not (op / 'closed.json').exists(), 'daily.operation.closed')
    need(not any(action_file(op, verb + '-' + generation, 'intent').exists() or
                 (op / ('attempt-current-' + verb + '-' + generation + '.json')).exists()
                 for verb in ('unmount', 'detach', 'delete')), 'daily.generation.teardown_started')


def settled_check(location):
    observed = trial.status(location)
    if not (location / 'start-intent.json').exists():
        need(observed['state'] == 'prepared', 'daily.native.unrequested_conflict')
        return observed
    need(observed['state'] in ('succeeded', 'failed'), 'daily.native.not_settled')
    result = observed['result']
    if (observed['state'] == 'failed' and result['cleanup'] == 'not_started' and
            result['containerId'] is None and result['nativeState'] is None):
        proof = durable.prove_trial_no_create_failure(location,
                    hash_bytes(durable.private_bytes(location / 'intent.json')))
        need(proof == result, 'daily.native.precreate_proof_changed')
        return observed
    need(result['cleanup'] == 'owned_container_stopped_retained', 'daily.native.cleanup_unknown')
    actual = trial.inspect_container(result['containerId'])
    trial.validate_owned_container(actual, result['containerId'], location)
    current, retained = actual['State'], result['nativeState']
    need(current['Running'] is False and current['Pid'] == 0 and
         all(current[key] == retained[key] for key in ('StartedAt', 'FinishedAt', 'ExitCode', 'OOMKilled')),
         'daily.native.container_changed')
    return observed


def generation_settled(op, generation):
    for phase in (('doctor', 'startup') if generation == 'candidate' else ('rollback',)):
        if (op / (phase + '.trial.json')).exists():
            location, _ = trial_binding(op, phase)
            settled_check(location)


def detached_mount_proof(op, run, generation):
    """Admit never-mounted/failed-mount cleanup only after dispatch is settled."""
    key = 'mount-' + generation
    intent_file = action_file(op, key, 'intent')
    if intent_file.exists():
        response = action_file(op, key, 'response')
        failure = action_file(op, key, 'host-failed')
        need(response.exists() or failure.exists(), 'daily.mount.dispatch_unsettled')
        if failure.exists():
            need(durable.read_private(failure)['intentSha256'] == hash_bytes(durable.private_bytes(intent_file)),
                 'daily.mount.failure_binding')
    info = device_info(run, generation)
    rows = mounted()
    root = mount_root(op, generation)
    no_container_users(root)
    need(not any(row['target'] == str(root) or row['maj:min'] == info['filesystemMajorMinor'] for row in rows),
         'daily.disk.still_mounted')
    return {'device': info, 'mountRoot': str(root), 'mounted': False}


def action(op, run, verb, generation, cloud):
    key, plan = action_key(verb, generation), run['plan']
    need(not (op / 'closed.json').exists(), 'daily.operation.closed')
    if verb in ('restore', 'attach', 'mount'):
        open_generation(op, generation)
    else:
        generation_settled(op, generation)
    vm, _, _ = observe_production(cloud, plan, run['production'])
    name, target = disk_name(run, generation), link(plan, 'disks', disk_name(run, generation))
    base = {'key': key, 'generation': generation, 'diskName': name, 'diskLink': target,
            'runSha256': hash_bytes(durable.private_bytes(op / 'run.json')), 'promotionAuthorized': False,
            **attempt_binding(op, key)}
    if verb in ('restore', 'attach', 'mount'):
        need(now() < contracts.utc(plan['expiresAt']), 'daily.plan.expired')
    if verb == 'restore':
        if generation == 'rollback':
            need(completed(op, 'delete-candidate') is not None, 'daily.rollback.candidate_not_deleted')
        current = api_get(cloud, target, True)
        need(current is None, 'daily.disk.name_collision')
        chosen = api_get(cloud, snapshot_link(plan, run['snapshot']['name']))
        need(str(chosen.get('id')) == str(run['snapshot']['id']) and chosen.get('status') == 'READY', 'daily.snapshot.changed')
        if generation == 'candidate':
            need(0 <= (now() - timestamp(chosen['creationTimestamp'])).total_seconds() <= plan['maxSnapshotAgeSeconds'],
                 'daily.snapshot.stale_at_restore')
        # Rollback deliberately uses the identical original snapshot even when
        # its age increases during a long candidate migration/startup check.
        base.update(method='POST', path=f"projects/{plan['project']}/zones/{plan['zone']}/disks", operationType='insert', targetLink=target,
                    body={'name': name, 'sizeGb': str(run['snapshot']['diskSizeGb']), 'type': f"https://compute.googleapis.com/compute/v1/projects/{plan['project']}/zones/{plan['zone']}/diskTypes/{plan['resources']['diskType']}",
                          'sourceSnapshot': run['snapshot']['selfLink'], 'labels': {'openclaw-run': op.name, 'openclaw-role': generation}})
        return base
    disk = owned_disk(cloud, op, run, generation)
    base['diskId'] = str(disk['id'])
    attached = attachment(vm, target)
    users = [canonical_link(user) for user in disk.get('users', [])]
    vm_ref = run['production']['instanceLink']
    need(all(user == vm_ref for user in users), 'daily.disk.foreign_user')
    if verb == 'attach':
        need(attached is None and not users, 'daily.disk.already_attached')
        base.update(method='POST', path=vm_ref + '/attachDisk', operationType='attachDisk', targetLink=vm_ref,
                    expectedTargetId=plan['instance']['id'], body={'source': 'https://compute.googleapis.com/compute/v1/' + target,
                        'deviceName': name, 'boot': False, 'autoDelete': False, 'mode': 'READ_WRITE', 'type': 'PERSISTENT'})
    elif verb in ('mount', 'unmount', 'detach'):
        need(attached is not None and attached.get('deviceName') == name and attached.get('boot') is False and
             attached.get('autoDelete') is False and attached.get('mode') == 'READ_WRITE', 'daily.disk.attachment_changed')
        need(completed(op, 'attach-' + generation) is not None, 'daily.disk.no_attachment_receipt')
        if verb == 'detach':
            base['unmountedObservation'] = detached_mount_proof(op, run, generation)
            base.update(method='POST', path=vm_ref + '/detachDisk', operationType='detachDisk', targetLink=vm_ref,
                        expectedTargetId=plan['instance']['id'], query={'deviceName': name}, body={})
        else:
            base.update(hostAction=verb, mountRoot=str(mount_root(op, generation)), deviceName=name,
                        device=device_info(run, generation))
    elif verb == 'delete':
        need(not attached and not users, 'daily.disk.in_use')
        never_attached = not action_file(op, 'attach-' + generation, 'intent').exists() or failed_action(op, 'attach-' + generation)
        need(never_attached or completed(op, 'detach-' + generation) is not None, 'daily.disk.detach_unsettled')
        no_container_users(mount_root(op, generation))
        need(not any(row['target'] == str(mount_root(op, generation)) for row in mounted()), 'daily.disk.still_mounted')
        verify_diagnostics(op, run, generation)
        base.update(method='DELETE', path=target, operationType='delete', targetLink=target, expectedTargetId=str(disk['id']), body=None,
                    destructiveEffect='Delete this exact disposable test disk including its database, scratch and optional cache. Retain the source snapshot and private diagnostics; create no full-disk backup.')
    return base


def challenge(value):
    return hash_bytes(durable.encode(value))


def claim(op):
    root = release.private_root(ROOT)
    with durable.operation_lock(root):
        owner_file = root / 'owner.json'
        if owner_file.exists():
            owner = durable.read_private(owner_file)
            if owner['operationId'] == op.name:
                return
            previous = root / owner['operationId']
            need(trial.OP.fullmatch(owner['operationId']) and (previous / 'closed.json').exists(), 'daily.owner.busy')
            closed = durable.read_private(previous / 'closed.json')
            need(closed.get('noOwnedResources') is True, 'daily.owner.uncertain')
            retain(root / ('settled-' + owner['operationId'] + '.json'), durable.encode(owner))
            # Owner transition is serialized. A crash before replacement leaves
            # the old closed owner; retry re-observes that same terminal proof.
            temporary = root / ('owner-' + op.name + '.tmp')
            temporary.write_bytes(durable.encode({'operationId': op.name}))
            temporary.chmod(0o600)
            with temporary.open('rb') as stream:
                os.fsync(stream.fileno())
            os.replace(temporary, owner_file)
            durable.sync_directory(root)
        else:
            record(root, 'owner.json', {'operationId': op.name})


def perform(op, verb, generation, approval, cloud):
    op, run = load(op)
    key = action_key(verb, generation)
    with durable.operation_lock(op):
        if action_file(op, key, 'intent').exists():
            return reconcile(op, key, cloud)
        intended = action(op, run, verb, generation, cloud)
        need(approval == challenge(intended), 'daily.action.approval_mismatch')
        claim(op)
        intended['requestId'] = str(uuid.uuid4())
        intended['requestedAt'] = durable.now()
        record(op, key + '.intent.json', intended)
        try:
            if 'hostAction' in intended:
                response = host_action(op, run, intended, cloud)
            else:
                query = {**intended.get('query', {}), 'requestId': intended['requestId']}
                response = cloud.request(intended['method'], intended['path'], body=intended['body'], query=query)
            record(op, key + '.response.json', response)
        except HostFailure:
            # Unlike a timeout/lost process, a returned nonzero native exit is
            # settled. Retain it so an attached but unmounted disk can detach.
            record(op, key + '.host-failed.json', {'state': 'failed', 'at': durable.now(),
                   'intentSha256': hash_bytes(durable.private_bytes(action_file(op, key, 'intent')))})
        except (OSError, subprocess.TimeoutExpired, ValueError, release.Refusal):
            # Keep the intent even for an apparent transport error. It does not
            # establish whether a side effect occurred; next calls only observe.
            preflight_only = 'hostAction' in intended and not action_file(op, key, 'host-ready').exists()
            record(op, key + ('.host-failed.json' if preflight_only else '.dispatch-unknown.json'),
                   {'state': 'failed' if preflight_only else 'unknown', 'at': durable.now(),
                    'intentSha256': hash_bytes(durable.private_bytes(action_file(op, key, 'intent')))})
        return reconcile(op, key, cloud)


def retry_prepare(op, verb, generation, cloud):
    """Prepare a new teardown attempt; apply still requires its fresh challenge."""
    op, run = load(op)
    key = action_key(verb, generation)
    need(verb in ('unmount', 'detach', 'delete'), 'daily.retry.teardown_only')
    with durable.operation_lock(op):
        need(not (op / 'closed.json').exists(), 'daily.operation.closed')
        previous = attempt_binding(op, key)
        old_intent = action_file(op, key, 'intent')
        if previous['attempt'] > 1 and not old_intent.exists():
            intended = action(op, run, verb, generation, cloud)
            return {'action': intended, 'approvalChallenge': challenge(intended), 'cloudMutationDispatched': False}
        state = reconcile(op, key, cloud)
        need(state['state'] == 'failed' and action_file(op, key, 'result').exists(), 'daily.retry.not_proven_failed')
        result_file = action_file(op, key, 'result')
        result = durable.read_private(result_file)
        need(result['intentSha256'] == hash_bytes(durable.private_bytes(old_intent)), 'daily.retry.failure_binding')
        intent = durable.read_private(old_intent)
        if 'hostAction' in intent:
            failure = durable.read_private(action_file(op, key, 'host-failed'))
            need(result.get('nativeHostFailure') == failure and failure['intentSha256'] == result['intentSha256'], 'daily.retry.host_unsettled')
        else:
            native_result = operation_receipt(result['nativeOperation'], intent['requestId'], intent['operationType'],
                              intent['targetLink'], intent.get('expectedTargetId'), allow_failed=True)
            need(native_result.get('error') or native_result.get('httpErrorStatusCode') or native_result.get('httpErrorMessage'),
                 'daily.retry.cloud_not_failed')
        # Fresh ownership/need-for-action checks precede preparing another
        # attempt. No cloud call is retried here and the prior result is kept.
        action(op, run, verb, generation, cloud)
        current = {'attempt': previous['attempt'] + 1, 'previousFailureSha256': hash_bytes(durable.private_bytes(result_file))}
        need(current['attempt'] <= 8, 'daily.retry.attempt_limit')
        directory = op / (key + '-attempt-' + str(current['attempt']))
        directory.mkdir(mode=0o700, exist_ok=True)
        need(directory.resolve() == directory and directory.stat().st_uid == os.getuid() and
             stat.S_IMODE(directory.stat().st_mode) == 0o700, 'daily.retry.directory_owner')
        retain(directory / 'retry-parent.json', durable.encode(current))
        need(not (directory / (key + '.intent.json')).exists(), 'daily.retry.pending_transition')
        temporary = op / ('attempt-pending-' + key + '-' + str(current['attempt']) + '.json')
        retain(temporary, durable.encode(current))
        os.replace(temporary, op / ('attempt-current-' + key + '.json'))
        durable.sync_directory(op)
        intended = action(op, run, verb, generation, cloud)
        return {'action': intended, 'approvalChallenge': challenge(intended), 'cloudMutationDispatched': False}


def device_info(run, generation):
    by_id = Path('/dev/disk/by-id') / ('google-' + disk_name(run, generation))
    device = by_id.resolve(strict=True)
    need(stat.S_ISBLK(device.stat().st_mode), 'daily.device.not_block')
    info = json.loads(host(['lsblk', '--json', '--paths', '--output', 'PATH,TYPE,FSTYPE,MAJ:MIN,MOUNTPOINTS', str(device)]))
    roots = info.get('blockdevices', [])
    need(len(roots) == 1 and roots[0]['path'] == str(device), 'daily.device.identity')
    rows = [roots[0], *roots[0].get('children', [])]
    need(len(rows) <= 16 and all(not row.get('children') for row in rows[1:]), 'daily.device.topology')
    filesystems = [row for row in rows if row.get('fstype') in ('ext4', 'xfs')]
    need(len(filesystems) == 1, 'daily.device.filesystem_ambiguous')
    fs = filesystems[0]
    native = Path(fs['path']).resolve(strict=True)
    need(stat.S_ISBLK(native.stat().st_mode), 'daily.device.filesystem_type')
    major_minor = f"{os.major(native.stat().st_rdev)}:{os.minor(native.stat().st_rdev)}"
    need(major_minor == fs['maj:min'] and native.stat().st_rdev != Path('/').stat().st_dev, 'daily.device.production_root')
    return {'devicePath': str(device), 'filesystemPath': str(native), 'deviceMajorMinor': roots[0]['maj:min'],
            'filesystemMajorMinor': major_minor, 'filesystemType': fs['fstype']}


def host_action(op, run, intended, cloud):
    generation = intended['generation']
    # Repeat cloud ownership immediately before touching the host mount table.
    disk = owned_disk(cloud, op, run, generation)
    need(str(disk['id']) == intended['diskId'], 'daily.disk.changed_before_mount')
    root = mount_root(op, generation)
    info = device_info(run, generation)
    need(info == intended['device'], 'daily.mount.device_changed_before_dispatch')
    rows = mounted()
    if intended['hostAction'] == 'mount':
        need(not any(row['maj:min'] == info['filesystemMajorMinor'] or row['target'] == str(root) for row in rows), 'daily.device.already_mounted')
        need(not root.exists(), 'daily.mount.path_exists')
        record(op, intended['key'] + '.host-ready.json', {'at': durable.now()})
        host(['sudo', '-n', 'install', '-d', '-m', '0700', '-o', str(os.getuid()), '-g', str(os.getgid()), str(root)])
        host(['sudo', '-n', 'mount', '-o', 'nosuid,nodev', info['filesystemPath'], str(root)], 120)
    else:
        retained = completed(op, 'mount-' + generation)
        need(retained is not None and retained['resource']['device'] == info, 'daily.mount.device_changed')
        matching = [row for row in rows if row['target'] == str(root)]
        need(len(matching) == 1 and matching[0]['maj:min'] == info['filesystemMajorMinor'], 'daily.mount.changed')
        no_container_users(root)
        record(op, intended['key'] + '.host-ready.json', {'at': durable.now()})
        # Native unmount refuses busy users; no lazy/force option is permitted.
        host(['sudo', '-n', 'umount', str(root)], 120)
    return {'hostAction': intended['hostAction'], 'diskId': intended['diskId'], 'device': info, 'observedAt': durable.now()}


def reconcile(op, key, cloud):
    op, run = load(op)
    intent_file = action_file(op, key, 'intent')
    if not intent_file.exists():
        return {'action': key, 'state': 'not_requested', 'promotionAuthorized': False}
    intended = durable.read_private(intent_file)
    result_file = action_file(op, key, 'result')
    if result_file.exists():
        return durable.read_private(result_file)
    plan, generation = run['plan'], intended['generation']
    observe_production(cloud, plan, run['production'])
    if 'hostAction' in intended:
        response_file = action_file(op, key, 'response')
        disk = owned_disk(cloud, op, run, generation)
        info = device_info(run, generation)
        need(str(disk['id']) == intended['diskId'] and info == intended['device'], 'daily.mount.reconcile_identity')
        if not response_file.exists():
            rows = mounted()
            root = str(mount_root(op, generation))
            found = [row for row in rows if row['target'] == root]
            if intended['hostAction'] == 'mount':
                proven = len(found) == 1 and found[0]['maj:min'] == info['filesystemMajorMinor']
            else:
                proven = completed(op, 'mount-' + generation) is not None and not found and not any(
                    row['maj:min'] == info['filesystemMajorMinor'] for row in rows)
                no_container_users(mount_root(op, generation))
            if not proven:
                failed = action_file(op, key, 'host-failed')
                if failed.exists():
                    need(durable.read_private(failed)['intentSha256'] == hash_bytes(durable.private_bytes(intent_file)), 'daily.mount.failure_binding')
                    result = {'action': key, 'state': 'failed', 'reason': 'native-host-command-returned-nonzero',
                              'intentSha256': hash_bytes(durable.private_bytes(intent_file)),
                              'nativeHostFailure': durable.read_private(failed), 'at': durable.now(),
                              'promotionAuthorized': False}
                    record(op, key + '.result.json', result)
                    return result
                return {'action': key, 'state': 'unknown', 'reason': 'host-postcondition-not-proven'}
            record(op, key + '.response.json', {'hostAction': intended['hostAction'], 'diskId': intended['diskId'],
                   'device': info, 'observedAt': durable.now(), 'reconciledFromNativeState': True})
        response = durable.read_private(response_file)
        rows = mounted()
        root = str(mount_root(op, generation))
        found = [row for row in rows if row['target'] == root]
        succeeded = (len(found) == 1 and found[0]['maj:min'] == response['device']['filesystemMajorMinor']) if intended['hostAction'] == 'mount' else not found
        need(succeeded, 'daily.mount.result_conflict')
        result = {'action': key, 'state': 'succeeded', 'at': durable.now(), 'resource': response,
                  'intentSha256': hash_bytes(durable.private_bytes(intent_file)), 'promotionAuthorized': False}
    else:
        response_file = action_file(op, key, 'response')
        response = durable.read_private(response_file) if response_file.exists() else None
        terminal_file = action_file(op, key, 'native-terminal')
        operation = durable.read_private(terminal_file) if terminal_file.exists() else response
        if not operation or operation.get('status') != 'DONE':
            operation = inspect_operation(cloud, plan['project'], plan['zone'], intended['requestId'],
                                          operation_name=response.get('name') if response else None)
        if operation is None:
            return {'action': key, 'state': 'unknown', 'reason': 'no-authoritative-operation-result'}
        if operation.get('status') != 'DONE':
            return {'action': key, 'state': 'running', 'operationName': operation.get('name')}
        # GCP guarantees completed operation retention for only one hour. Keep
        # its native terminal bytes before checking the resulting resource.
        retain(terminal_file, durable.encode(operation))
        native_result = operation_receipt(operation, intended['requestId'], intended['operationType'],
                                          intended['targetLink'], intended.get('expectedTargetId'), allow_failed=True)
        if operation.get('error') or operation.get('httpErrorStatusCode') or operation.get('httpErrorMessage'):
            result = {'action': key, 'state': 'failed', 'at': durable.now(), 'nativeOperation': native_result,
                      'intentSha256': hash_bytes(durable.private_bytes(intent_file)), 'promotionAuthorized': False}
            record(op, key + '.result.json', result)
            return result
        disk = api_get(cloud, intended['diskLink'], True)
        if key.startswith('restore-'):
            need(disk is not None and str(disk.get('id')) == str(operation['targetId']) and
                 str(disk.get('sourceSnapshotId')) == str(run['snapshot']['id']) and
                 canonical_link(disk['sourceSnapshot']) == canonical_link(run['snapshot']['selfLink']) and
                 disk.get('status') == 'READY' and not disk.get('users') and
                 disk.get('labels', {}).get('openclaw-run') == op.name and
                 disk.get('labels', {}).get('openclaw-role') == generation, 'daily.restore.result_mismatch')
            resource = {'id': str(disk['id']), 'selfLink': canonical_link(disk['selfLink']),
                        'sourceSnapshotId': str(disk['sourceSnapshotId']), 'sizeGb': str(disk['sizeGb'])}
        elif key.startswith('delete-'):
            need(disk is None, 'daily.delete.resource_still_present')
            resource = {'id': intended['diskId'], 'selfLink': intended['diskLink'], 'deleted': True}
        else:
            need(disk is not None and str(disk.get('id')) == intended['diskId'], 'daily.disk.changed_during_attach')
            vm = api_get(cloud, run['production']['instanceLink'])
            attached = attachment(vm, intended['diskLink'])
            if key.startswith('attach-'):
                need(attached is not None and attached.get('deviceName') == intended['diskName'] and attached.get('boot') is False and attached.get('autoDelete') is False, 'daily.attach.result_mismatch')
            else:
                need(attached is None and not disk.get('users'), 'daily.detach.result_mismatch')
            resource = {'id': intended['diskId'], 'selfLink': intended['diskLink'], 'attached': attached is not None}
        result = {'action': key, 'state': 'succeeded', 'at': durable.now(), 'resource': resource,
                  'nativeOperation': native_result, 'intentSha256': hash_bytes(durable.private_bytes(intent_file)),
                  'promotionAuthorized': False}
    record(op, key + '.result.json', result)
    return result


def archive_diagnostics(op, generation):
    op, run = load(op)
    need(generation in GENERATIONS, 'daily.generation')
    destination = op / (generation + '.diagnostics.json')
    if destination.exists():
        return verify_diagnostics(op, run, generation)
    entries = {}
    for phase in (('doctor', 'startup') if generation == 'candidate' else ('rollback',)):
        binding_path = op / (phase + '.trial.json')
        if not binding_path.exists():
            continue
        binding = durable.read_private(binding_path)
        operation = trial.PRIVATE_ROOT / binding['operationId']
        status = settled_check(operation)
        target = op / ('diagnostics-' + phase)
        target.mkdir(mode=0o700, exist_ok=True)
        need(target.resolve() == target and stat.S_IMODE(target.stat().st_mode) == 0o700 and target.stat().st_uid == os.getuid(), 'daily.diagnostics.owner')
        files = {}
        for name in ('intent.json', 'started.json', 'result.json', 'native-settlement.json', 'resources.jsonl',
                     'stdout.log', 'stdout.log.previous', 'stderr.log', 'stderr.log.previous'):
            source = operation / name
            if source.exists():
                raw = durable.private_bytes(source)
                need(len(raw) <= 16 << 20, 'daily.diagnostics.limit')
                retain(target / name, raw)
                files[name] = hash_bytes(raw)
        entries[phase] = {'operationId': binding['operationId'], 'state': status['state'], 'files': files}
    result = {'schema': 'openclaw.daily-diagnostics.v1', 'generation': generation,
              'runSha256': hash_bytes(durable.private_bytes(op / 'run.json')), 'checks': entries,
              'at': durable.now(), 'containsDatabaseCopy': False, 'fullDiskSnapshotCreated': False}
    record(op, generation + '.diagnostics.json', result)
    return result


def verify_diagnostics(op, run, generation):
    file = op / (generation + '.diagnostics.json')
    need(file.exists(), 'daily.diagnostics.not_retained')
    value = durable.read_private(file)
    need(value.get('schema') == 'openclaw.daily-diagnostics.v1' and value.get('generation') == generation and
         value.get('runSha256') == hash_bytes(durable.private_bytes(op / 'run.json')), 'daily.diagnostics.binding')
    for phase in (('doctor', 'startup') if generation == 'candidate' else ('rollback',)):
        binding_file = op / (phase + '.trial.json')
        if not binding_file.exists():
            need(phase not in value['checks'], 'daily.diagnostics.extra_check')
            continue
        binding = durable.read_private(binding_file)
        retained = value['checks'].get(phase)
        need(retained is not None and retained['operationId'] == binding['operationId'], 'daily.diagnostics.missing_check')
        observed = settled_check(trial.PRIVATE_ROOT / binding['operationId'])
        need(observed['state'] == retained['state'], 'daily.native.not_settled')
        need(('result.json' if observed['state'] != 'prepared' else 'intent.json') in retained['files'], 'daily.diagnostics.missing_result')
        for name, hashed in retained['files'].items():
            need(Path(name).name == name and HEX.fullmatch(hashed) and
                 hash_bytes(durable.private_bytes(op / ('diagnostics-' + phase) / name)) == hashed,
                 'daily.diagnostics.changed')
    return value


def trial_binding(op, phase):
    need(phase in ('doctor', 'startup', 'rollback'), 'daily.check.phase')
    binding = durable.read_private(op / (phase + '.trial.json'))
    expected = uuid.uuid5(uuid.UUID(hex=op.name), phase).hex
    need(binding['operationId'] == expected, 'daily.check.operation_id')
    location, intent = trial.load(trial.PRIVATE_ROOT / expected)
    need(hash_bytes(durable.private_bytes(location / 'intent.json')) == binding['intentSha256'], 'daily.check.binding')
    return location, intent


def clean_binding(op, run, phase, clean, cloud):
    generation = 'rollback' if phase == 'rollback' else 'candidate'
    disk = owned_disk(cloud, op, run, generation)
    root = mount_root(op, generation)
    retained = completed(op, 'mount-' + generation)
    need(retained is not None and retained['resource']['diskId'] == str(disk['id']), 'daily.check.mount_receipt')
    info = device_info(run, generation)
    need(retained['resource']['device'] == info, 'daily.check.device_changed')
    rows = [row for row in mounted() if row['target'] == str(root)]
    need(len(rows) == 1 and rows[0]['maj:min'] == info['filesystemMajorMinor'], 'daily.check.not_mounted')
    need(clean['mountRoot'] == str(root) and clean['filesystemDevice'] == root.stat().st_dev and
         clean['devicePath'] == info['devicePath'] and clean['deviceMajorMinor'] == info['deviceMajorMinor'], 'daily.check.device_binding')
    need(clean['restoreReceiptSha256'] == hash_bytes(durable.private_bytes(action_file(op, 'restore-' + generation, 'result'))) and
         clean['snapshotIdentity'] == str(run['snapshot']['id']), 'daily.check.snapshot_binding')
    baseline = run['plan']['baselineImage']
    need(clean['baselineSourceSha'] == baseline['sourceSha'] and
         clean['baselineImageDigest'] in {baseline[k] for k in ('indexDigest', 'imageDigest', 'configDigest')}, 'daily.check.baseline_binding')
    # Source paths and config are checked by the existing trial owner without
    # recursive inventory, reconstruction, or copying the snapshot databases.
    trial.snapshot_paths(clean)


def prepare_check(op, phase, clean_path, tooling, cloud):
    op, run = load(op)
    need(phase in ('doctor', 'startup', 'rollback'), 'daily.check.phase')
    with durable.operation_lock(op):
        if (op / (phase + '.trial.json')).exists():
            location, _ = trial_binding(op, phase)
            return {'operation': str(location), 'state': trial.status(location)['state']}
        open_generation(op, 'rollback' if phase == 'rollback' else 'candidate')
        need(now() < contracts.utc(run['plan']['expiresAt']), 'daily.plan.expired')
        observe_production(cloud, run['plan'], run['production'])
        clean_raw = durable.private_bytes(clean_path)
        clean = json.loads(clean_raw)
        clean_binding(op, run, phase, clean, cloud)
        check = {'schema': 'openclaw.snapshot-trial-check.v1', 'phase': phase}
        if phase != 'doctor':
            previous, _ = trial_binding(op, 'doctor')
            prior = trial.status(previous)
            need(prior['state'] in (('succeeded',) if phase == 'startup' else ('succeeded', 'failed')), 'daily.check.doctor_unsettled')
            check.update(doctorOperationId=previous.name, doctorResultSha256=hash_bytes(durable.private_bytes(previous / 'result.json')))
        image_raw = (durable.encode({'schema': 'openclaw.rehearsal-baseline-image.v1', 'architecture': 'amd64', **run['plan']['baselineImage']})
                     if phase == 'rollback' else durable.private_bytes(op / 'image-receipt.json'))
        check_raw = durable.encode(check)
        plan = {'schema': 'openclaw.snapshot-trial-plan.v2', 'phase': phase,
                'operationId': uuid.uuid5(uuid.UUID(hex=op.name), phase).hex, 'toolingSha': run['plan']['toolingSha'],
                'imageReceiptSha256': hash_bytes(image_raw), 'cleanInputSha256': hash_bytes(clean_raw),
                'checkInputSha256': hash_bytes(check_raw),
                'limits': {k: v for k, v in run['plan']['resources'].items() if k not in
                           ('diskType', 'maxDiskGiB', 'estimatedCostMicrousd', 'approvedCostMicrousd')}}
        trial.validate(plan, json.loads(image_raw), clean, check)
        inputs = op / (phase + '-input')
        inputs.mkdir(mode=0o700, exist_ok=True)
        need(inputs.resolve() == inputs and inputs.stat().st_uid == os.getuid() and stat.S_IMODE(inputs.stat().st_mode) == 0o700, 'daily.check.input_owner')
        for name, raw in (('plan.json', durable.encode(plan)), ('image.json', image_raw), ('clean.json', clean_raw), ('check.json', check_raw)):
            retain(inputs / name, raw)
        location = trial.PRIVATE_ROOT / plan['operationId']
        if location.exists():
            location, existing = trial.load(location)
            need(existing['plan'] == plan, 'daily.check.existing_conflict')
        else:
            location = trial.prepare(inputs / 'plan.json', inputs / 'image.json', inputs / 'clean.json', tooling, inputs / 'check.json')
        record(op, phase + '.trial.json', {'operationId': location.name,
                                         'intentSha256': hash_bytes(durable.private_bytes(location / 'intent.json'))})
        return {'operation': str(location), 'state': 'prepared', 'promotionAuthorized': False}


def check_action(op, phase, cloud):
    op, run = load(op)
    location, intent = trial_binding(op, phase)
    open_generation(op, 'rollback' if phase == 'rollback' else 'candidate')
    need(now() < contracts.utc(run['plan']['expiresAt']), 'daily.plan.expired')
    observe_production(cloud, run['plan'], run['production'])
    clean_binding(op, run, phase, intent['clean'], cloud)
    trial.phase_prerequisites(location, intent)
    return {'action': 'native-' + phase, 'operationId': location.name,
            'intentSha256': hash_bytes(durable.private_bytes(location / 'intent.json')),
            'imageDigest': intent['image']['indexDigest'], 'limits': intent['plan']['limits'],
            'effect': 'Run one isolated native phase on the owned disposable snapshot clone; retain failures and logs.',
            'promotionAuthorized': False}


def run_check(op, phase, approval, cloud):
    op, _ = load(op)
    with durable.operation_lock(op):
        location, _ = trial_binding(op, phase)
        if (location / 'start-intent.json').exists():
            return trial.status(location)
        intended = check_action(op, phase, cloud)
        need(approval == challenge(intended), 'daily.action.approval_mismatch')
        claim(op)
        # The shared trial/build admission lock owns fresh capacity, exclusive
        # heavyweight dispatch, durable start intent and uncertain reconciliation.
        return trial.start(location)


def _status(op, cloud):
    op, run = load(op)
    actions = {}
    for generation in GENERATIONS:
        for verb in VERBS:
            key = action_key(verb, generation)
            if action_file(op, key, 'intent').exists() or (op / ('attempt-current-' + key + '.json')).exists():
                actions[key] = reconcile(op, key, cloud)
    checks = {}
    for phase in ('doctor', 'startup', 'rollback'):
        file = op / (phase + '.trial.json')
        if file.exists():
            binding = durable.read_private(file)
            checks[phase] = trial.status(trial.PRIVATE_ROOT / binding['operationId'])
    return {'operationId': op.name, 'snapshotId': str(run['snapshot']['id']), 'actions': actions, 'checks': checks,
            'expired': now() >= contracts.utc(run['plan']['expiresAt']), 'promotionAuthorized': False,
            'cleanupAutomatic': False, 'productionActionAvailable': False}


def status(op, cloud):
    op, _ = load(op)
    with durable.operation_lock(op):
        return _status(op, cloud)


def close(op, cloud):
    op, run = load(op)
    with durable.operation_lock(op):
        if (op / 'closed.json').exists():
            return durable.read_private(op / 'closed.json')
        state = _status(op, cloud)
        for generation in GENERATIONS:
            key = 'restore-' + generation
            if action_file(op, key, 'intent').exists():
                deleted = 'delete-' + generation
                need((failed_action(op, key) or failed_action(op, deleted) or completed(op, deleted) is not None) and
                     api_get(cloud, link(run['plan'], 'disks', disk_name(run, generation)), True) is None, 'daily.close.resource_unsettled')
        for generation in GENERATIONS:
            generation_settled(op, generation)
        qualified = all(state['checks'].get(phase, {}).get('state') == 'succeeded' for phase in ('doctor', 'startup', 'rollback'))
        result = {'state': 'qualified' if qualified else 'closed_without_qualification', 'at': durable.now(),
                  'noOwnedResources': True, 'promotionAuthorized': False, 'productionDatabase': 'must-use-fresh-current-production-capture'}
        record(op, 'closed.json', result)
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    make = commands.add_parser('prepare')
    for name in ('plan', 'image-receipt', 'tooling'):
        make.add_argument('--' + name, type=Path, required=True)
    for command in ('status', 'close', 'archive', 'action', 'apply', 'retry-prepare', 'prepare-check', 'check-action', 'run-check'):
        item = commands.add_parser(command)
        item.add_argument('operation', type=Path)
        if command in ('action', 'apply', 'retry-prepare'):
            item.add_argument('verb', choices=VERBS)
        if command in ('archive', 'action', 'apply', 'retry-prepare'):
            item.add_argument('generation', choices=GENERATIONS)
        if command in ('prepare-check', 'check-action', 'run-check'):
            item.add_argument('phase', choices=('doctor', 'startup', 'rollback'))
        if command in ('apply', 'run-check'):
            item.add_argument('--approve', required=True)
        if command == 'prepare-check':
            item.add_argument('--clean-input', type=Path, required=True)
            item.add_argument('--tooling', type=Path, required=True)
    args = parser.parse_args(argv)
    cloud = Cloud()
    try:
        if args.command == 'prepare':
            value = {'operation': str(prepare(args.plan, args.image_receipt, args.tooling, cloud)),
                     'state': 'prepared', 'cloudMutationDispatched': False}
        elif args.command == 'action':
            op, run = load(args.operation)
            value = action(op, run, args.verb, args.generation, cloud)
            value = {'action': value, 'approvalChallenge': challenge(value)}
        elif args.command == 'apply':
            value = perform(args.operation, args.verb, args.generation, args.approve, cloud)
        elif args.command == 'retry-prepare':
            value = retry_prepare(args.operation, args.verb, args.generation, cloud)
        elif args.command == 'status':
            value = status(args.operation, cloud)
        elif args.command == 'close':
            value = close(args.operation, cloud)
        elif args.command == 'archive':
            op, _ = load(args.operation)
            with durable.operation_lock(op):
                value = archive_diagnostics(op, args.generation)
        elif args.command == 'prepare-check':
            value = prepare_check(args.operation, args.phase, args.clean_input, args.tooling, cloud)
        elif args.command == 'check-action':
            value = check_action(args.operation, args.phase, cloud)
            value = {'action': value, 'approvalChallenge': challenge(value)}
        else:
            value = run_check(args.operation, args.phase, args.approve, cloud)
        print(json.dumps(value))
        return 0
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError, release.Refusal):
        # Local paths, tokens and provider errors stay out of public receipts.
        print(json.dumps({'state': 'refused', 'reason': 'daily.input_or_observation_invalid',
                          'retryMutation': False, 'promotionAuthorized': False}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
