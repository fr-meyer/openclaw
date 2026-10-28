"""Mac-side adjudication of one source-bound guest snapshot.

The caller must first establish the exact VM/IAP/guest script generation and
retain raw bytes privately. This module accepts no guest verdict as authority.
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path

import controller
import probe
import profile
from protocol import Refusal, canonical, closed, require, sha, utc
from snapshot_wire import ReplayReader

ANCHOR_KEYS = ('mounts', 'inheritedPaths', 'executable', 'jailRoot', 'stdio')
GUEST_SOURCE_BUNDLE_SHA256 = None


def evaluate(capture, context, owner, *, now):
    """Replay every ordered read against independently supplied owner identity.

    ``owner`` is sourced from the existing cloud/start/strict SSH receipts,
    never copied from this capture. No gate file is written by this function.
    """
    return _evaluate(capture, context, owner, now=now,
                     source_sha=GUEST_SOURCE_BUNDLE_SHA256)


def evaluate_bound(capture, context, owner, *, now, capability):
    """Use the reviewed outer issuer's opaque generation/source binding."""
    import native_authority
    source_sha = native_authority.require_source_binding(capability, owner)
    return _evaluate(capture, context, owner, now=now, source_sha=source_sha)


def _evaluate(capture, context, owner, *, now, source_sha):
    closed(owner, {'vmId', 'bootId', 'sessionId', 'unitName', 'guestSourceSha256'},
           'replay.owner_schema')
    require(owner['vmId'] == controller.VM_ID and
            type(source_sha) is str and
            owner['guestSourceSha256'] == source_sha and
            all(context[k] == owner[k] for k in ('bootId', 'sessionId', 'unitName', 'vmId')) and
            type(now) is dt.datetime and now.tzinfo is not None,
            'replay.owner_join')
    closed(capture, {'schema', 'expected', 'unit', 'binding', 'snapshot',
                     'guestProofSha256'}, 'replay.capture_schema')
    require(capture['schema'] == 'openclaw.private-host-capture.v1' and
            type(capture['snapshot']) is bytes and
            type(capture['guestProofSha256']) is str and
            len(capture['guestProofSha256']) == 64, 'replay.capture_shape')
    expected, unit, binding = capture['expected'], capture['unit'], capture['binding']
    probe.validate_expected(expected)
    require(type(binding) is dict and
            all(binding.get(k) == owner[k] for k in ('bootId', 'sessionId', 'unitName')) and
            binding.get('pid') == expected['pid'] and
            binding.get('startTimeTicks') == expected['startTimeTicks'] and
            binding.get('invocationId') == expected['invocationId'] and
            binding.get('profileSha256') == profile.DESIGN_PROFILE_SHA and
            binding.get('sourceAnchorSha256') ==
            sha(canonical({k: expected[k] for k in ANCHOR_KEYS})),
            'replay.binding_join')
    began, finished = utc(binding['startedAtUtc']), utc(binding['finishedAtUtc'])
    require(dt.timedelta(0) <= finished - began <= dt.timedelta(seconds=20) and
            dt.timedelta(0) <= now - finished <= dt.timedelta(seconds=30),
            'replay.stale_snapshot')
    require(all(expected[k] == owner[k] for k in ('bootId', 'sessionId', 'unitName')) and
            expected['profileSha256'] == profile.DESIGN_PROFILE_SHA and
            expected['identityName'] == context['identityName'],
            'replay.expected_join')
    template = (Path(__file__).resolve().parent / 'PROFILE.template.private.json').read_bytes()
    properties = profile.properties(template, context['sessionId'],
                                    '/var/lib/openclaw-retained-verifier/' + context['sessionId'])
    controller.unit_binding(unit, expected, context, sha(canonical(properties)))
    reader = ReplayReader(capture['snapshot'], binding)
    proof = probe.collect_and_validate(reader, expected)
    consumed = reader.finish()
    require(sha(canonical(proof)) == capture['guestProofSha256'], 'replay.proof_changed')
    return {'schema': 'openclaw.private-host-replay.v1', 'status': 'passed',
            'proof': proof, 'snapshot': consumed,
            'ownerGuestSourceSha256': owner['guestSourceSha256']}


if __name__ == '__main__':
    raise SystemExit('mac_replay_no_cli')
