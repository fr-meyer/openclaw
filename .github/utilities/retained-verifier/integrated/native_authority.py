"""Opaque source/owner session capabilities. No operational issuer exists yet.

The implementation components may be tested with explicitly bound synthetic IO.
Native issuance must later join the actual sole owner, reviewed source bundle,
authenticated runtime and measured VM tools. JSON cannot construct this class.
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import re
from types import MappingProxyType
from protocol import Refusal, canonical, read_regular, require, sha, utc

VM_ID = '1'
SOURCE_BASE = '/var/lib/openclaw-retained-verifier-source'
SESSION_BASE = '/var/lib/openclaw-retained-verifier'
_KEY = object()
OWNER_KEYS = frozenset(('vmId','bootId','sessionId','unitName','guestSourceSha256',
                        'providerStopAt','executionDeadlineUtc'))
APPROVED_NATIVE_REVIEW_SHA = None
APPROVED_SOURCE_BUNDLE_SHA = None
APPROVED_SDK_RELEASE_SHA = None
APPROVED_VM_TOOL_RECEIPT_SHA = None


def validate_owner(owner):
    require(type(owner) is dict and set(owner) == OWNER_KEYS and
            all(type(v) is str for v in owner.values()), 'native.owner_schema')
    require(owner['vmId'] == VM_ID and re.fullmatch('[0-9a-f]{32}',owner['sessionId']) and
            owner['unitName'] == 'ocv-'+owner['sessionId']+'.service' and
            re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}',owner['bootId']) and
            re.fullmatch('[0-9a-f]{64}',owner['guestSourceSha256']), 'native.owner_identity')
    require(utc(owner['providerStopAt']) + dt.timedelta(seconds=600) <=
            utc(owner['executionDeadlineUtc']), 'native.shutdown_reserve')


class SessionCapability:
    __slots__ = ('_key','_kind','_owner','_context','_pins','_ios','_runtime_source',
                 '_owner_guard','_grant','_channel','_io_types','_sealed')
    def __setattr__(self, name, value):
        require(not getattr(self,'_sealed',False), 'native.capability_immutable')
        object.__setattr__(self,name,value)
    def __delattr__(self, _name):
        raise Refusal('native.capability_immutable')
    def __init__(self, key, kind, owner, context, pins, ios, runtime_source=None,
                 owner_guard=None, grant=None, channel=None):
        require(key is _KEY, 'native.capability_unissued')
        validate_owner(owner)
        require(type(context) is dict and all(context.get(k)==owner[k] for k in
                ('vmId','bootId','sessionId','unitName')), 'native.context_owner')
        require(type(pins) is dict and type(ios) is dict, 'native.capability_shape')
        self._key,self._kind = key,kind
        self._owner,self._context,self._pins = canonical(owner),canonical(context),canonical(pins)
        self._ios = MappingProxyType(dict(ios))
        self._runtime_source = runtime_source
        self._owner_guard = owner_guard
        self._grant,self._channel=grant,channel
        self._io_types=MappingProxyType({role:type(io) for role,io in ios.items()})
        self._sealed = True

    @property
    def kind(self): return self._kind
    @property
    def owner(self): return json.loads(self._owner)
    @property
    def context(self): return json.loads(self._context)
    @property
    def pins(self): return json.loads(self._pins)
    @property
    def session_root(self): return Path(SESSION_BASE)/self.owner['sessionId']
    @property
    def source_root(self): return Path(SOURCE_BASE)/self.owner['guestSourceSha256']
    @property
    def runtime_source(self):
        require(self._runtime_source is not None, 'native.runtime_source_unissued')
        return self._runtime_source


def require_capability(capability, role, io):
    require(type(capability) is SessionCapability and capability._key is _KEY and
            capability._ios.get(role) is io, 'native.capability_unissued')
    if capability.kind=='synthetic-contract':
        require(_synthetic_io(io),'native.operational_issuer_unissued')
    elif capability.kind=='private-mac':
        require(role in ('mac','outer_stop') and type(io) is capability._io_types[role]
                and not _synthetic_io(io),'native.mac_purpose')
        if role=='outer_stop':capability._grant.require_cleanup_live()
        else:capability._grant.require_live()
    elif capability.kind in ('private-bootstrap','ci-bootstrap'):
        from preliminary_observer import NativeObservationIO
        require(role=='observer' and type(io) is NativeObservationIO,
                'native.bootstrap_purpose')
        capability._grant.require_live()
    else:
        require(capability.kind in ('private-native','ci-native-proof') and
                type(io) is capability._io_types[role] and
                not _synthetic_io(io),'native.operational_issuer_unissued')
        capability._grant.require_live()
        require_owner_guard(capability,io)
    return capability


def require_source_binding(capability, owner):
    """Join an issued session's source without embedding its own bundle hash."""
    require(type(capability) is SessionCapability and capability._key is _KEY and
            capability.kind in ('synthetic-contract','private-native','ci-native-proof','private-mac'),
            'native.source_binding_unissued')
    require(type(owner) is dict and set(owner) ==
            {'vmId','bootId','sessionId','unitName','guestSourceSha256'} and
            all(capability.owner[k] == v for k,v in owner.items()),
            'native.source_binding_owner')
    return capability.owner['guestSourceSha256']


def require_owner_guard(capability, io):
    """Known-task scheduling evidence alone never issues a native VM lease."""
    require(type(capability) is SessionCapability and capability._key is _KEY,
            'native.owner_guard_unissued')
    if capability.kind == 'synthetic-contract':
        require(any(bound is io for bound in capability._ios.values()) and
                _synthetic_io(io), 'native.synthetic_owner_guard')
        return {'kind':'synthetic-contract','owner':capability.owner,
                'nativeVMOwnershipEstablished':False}
    from owner_guard import OwnerGuard
    guard=io if type(io) is OwnerGuard and capability.kind in \
        ('private-bootstrap','ci-bootstrap') else capability._owner_guard
    require(type(guard) is OwnerGuard and (io is guard or
            any(bound is io for bound in capability._ios.values())),
            'native.owner_guard_unissued')
    return guard.verify_for(capability)


def require_bootstrap_capability(capability,role,io):
    require(type(capability) is SessionCapability and capability._key is _KEY and
            capability.kind in ('private-bootstrap','ci-bootstrap') and
            capability._ios.get(role) is io,'native.bootstrap_unissued')
    capability._grant.require_live()
    return capability


def _grant_kind(grant):
    name=type(grant).__module__
    if name=='ci_authority':
        from ci_authority import CIGrant
        require(type(grant) is CIGrant,'native.ci_grant_unissued')
        return 'ci'
    if name=='private_issuance':
        from private_issuance import InlineSourceGrant
        require(type(grant) is InlineSourceGrant,'native.private_grant_unissued')
        return 'private'
    raise Refusal('native.source_grant_unissued')


def _issue_bootstrap_from_verified_grant(grant,owner,context,pins,ios,
                                        runtime_source=None,channel=None):
    kind=_grant_kind(grant)
    grant.require_for('bootstrap',owner,context,pins,ios,runtime_source)
    grant.require_channel(channel)
    return SessionCapability(_KEY,kind+'-bootstrap',owner,context,pins,ios,
                             runtime_source,grant=grant,channel=channel)


def _issue_operational_from_verified_grant(grant,owner,context,pins,ios,
        runtime_source,bootstrap,owner_guard,channel=None):
    import guest_bootstrap
    kind=_grant_kind(grant)
    require(type(bootstrap) is guest_bootstrap.VerifiedBootstrap and
            bootstrap.owner==owner and bootstrap.bundle_sha256==owner['guestSourceSha256'] and
            bootstrap.manifest_sha256==pins.get('sourceManifestSha256') and
            bootstrap.owner_guard is owner_guard,'native.verified_bootstrap_required')
    grant.require_for('operational',owner,context,pins,ios,runtime_source,bootstrap=bootstrap)
    grant.require_channel(channel)
    cap=SessionCapability(_KEY,'private-native' if kind=='private' else 'ci-native-proof',
        owner,context,pins,ios,runtime_source,owner_guard,grant,channel)
    require_owner_guard(cap,owner_guard)
    return cap


def issue_ci_native(parent,prepared,owner,context,pins,ios,runtime_source):
    from ci_authority import issue_session
    return issue_session(parent,prepared,owner,context,pins,ios,runtime_source)


def _issue_mac_from_verified_grant(grant,owner,context,pins,ios):
    from private_issuance import MacSourceGrant
    require(type(grant) is MacSourceGrant,'native.mac_source_unissued')
    grant.require_for(owner,context,pins,ios)
    return SessionCapability(_KEY,'private-mac',owner,context,pins,ios,grant=grant)


def _issue_candidate_from_verified_grant(grant,owner,context,pins,ios,
                                        bootstrap,owner_guard,retained_pass):
    require(_grant_kind(grant)=='private','native.candidate_private_source')
    import guest_bootstrap
    require(type(bootstrap) is guest_bootstrap.VerifiedBootstrap and
            bootstrap.owner==owner and bootstrap.owner_guard is owner_guard and
            bootstrap.bundle_sha256==owner['guestSourceSha256'],
            'native.candidate_bootstrap')
    grant.require_for('candidate',owner,context,pins,ios,None,bootstrap=bootstrap,
                      retained_pass=retained_pass)
    cap=SessionCapability(_KEY,'private-native',owner,context,pins,ios,
                         owner_guard=owner_guard,grant=grant)
    require_owner_guard(cap,owner_guard)
    return cap


def require_authenticated_peer_channel(cap,receipt,purpose):
    require(type(cap) is SessionCapability and cap._key is _KEY and
            (cap.kind,purpose) in (('private-bootstrap','private-owned-ssh'),
                                  ('ci-bootstrap','ci-native-proof')) and
            receipt is cap._channel and receipt is not None and type(receipt) is not dict,
            'native.authenticated_channel_unissued')
    cap._grant.require_channel(receipt)
    return receipt


def require_verified_core(capability,core):
    """Preserve one verified module/class universe in the cached source loader."""
    import sys
    import types
    require(type(capability) is SessionCapability and capability._key is _KEY and
            capability.kind in ('private-bootstrap','ci-bootstrap') and
            type(core) is dict and {'native_authority','protocol','guest_bootstrap'}<=set(core),
            'native.verified_core_unissued')
    rows=capability.pins.get('trustedCoreSources')
    require(type(rows) is dict and 3<=len(rows)<=128 and set(core)<=set(rows),
            'native.core_schema')
    for name,row in rows.items():
        require(type(name) is str and re.fullmatch('[a-z][a-z0-9_]*',name) and
                type(row) is dict and set(row)=={'path','bytes','sha256'} and
                row['path']=='guest/'+name+'.py' and type(row['bytes']) is int and
                0<row['bytes']<=131072 and type(row['sha256']) is str and
                re.fullmatch('[0-9a-f]{64}',row['sha256']), 'native.core_row')
    for name,module in core.items():
        row=rows[name]
        require(type(name) is str and re.fullmatch('[a-z][a-z0-9_]*',name) and
                type(module) is types.ModuleType and sys.modules.get(name) is module and
                type(row) is dict and set(row)=={'path','bytes','sha256'} and
                row['path']=='guest/'+name+'.py' and type(row['bytes']) is int and
                0<row['bytes']<=131072 and type(row['sha256']) is str and
                re.fullmatch('[0-9a-f]{64}',row['sha256']), 'native.core_row')
        path=capability.source_root/row['path']
        require(path.is_file() and not path.is_symlink() and path.resolve()==path and
                Path(module.__file__)==path,'native.core_path')
        raw=read_regular(path,row['bytes'],expected_size=row['bytes'],
                         expected_sha=row['sha256'])
    require(core['native_authority'] is sys.modules[__name__],'native.core_identity')
    return core


def require_time(capability, now, *, cleanup=False, reserve=0):
    require(type(now) is dt.datetime and now.tzinfo is not None and type(reserve) is int
            and reserve >= 0, 'native.clock')
    owner=capability.owner
    stop=utc(owner['providerStopAt'])
    end=min(stop+dt.timedelta(seconds=600),utc(owner['executionDeadlineUtc'])) if cleanup else stop
    require(now + dt.timedelta(seconds=reserve) < end, 'native.deadline')


def _synthetic_io(io):
    """A synthetic class declaration cannot disguise native effect methods."""
    return (type(io).__dict__.get('evidence_kind') == 'synthetic_contract' and
            getattr(io,'evidence_kind',None) == 'synthetic_contract' and
            all(base.__dict__.get('evidence_kind') in (None,'synthetic_contract')
                for base in type(io).__mro__))


def synthetic_capability(owner, context, *, pins=None, ios, runtime_source=None):
    """Test injection only; every bound IO must be an explicit synthetic port."""
    require(type(ios) is dict and ios and all(_synthetic_io(io)
            for io in ios.values()), 'native.synthetic_io')
    return SessionCapability(_KEY,'synthetic-contract',owner,context,pins or {},ios,runtime_source)


class _OneUsePermit:
    __slots__ = ('_key','_role','_cap','_context_sha','_record','_used','_sealed')
    def __setattr__(self,name,value):
        require(not getattr(self,'_sealed',False), 'native.permit_immutable')
        object.__setattr__(self,name,value)
    def __delattr__(self, _name):
        raise Refusal('native.permit_immutable')
    def __init__(self,key,role,cap,context,record):
        require(key is _KEY and type(cap) is SessionCapability, 'native.permit_unissued')
        self._key,self._role,self._cap=key,role,cap
        self._context_sha,self._record=sha(canonical(context)),canonical(record)
        self._used=False;self._sealed=True
    def consume(self,role,cap,context):
        require(self._key is _KEY and self._role==role and self._cap is cap and
                not self._used and self._context_sha==sha(canonical(context)),
                'native.permit_join_or_consumed')
        object.__setattr__(self,'_used',True)  # Intent before any downstream effect.
        return json.loads(self._record)


def require_release_permit(permit,cap,context,gate):
    require(type(permit) is _OneUsePermit, 'native.release_permit_unissued')
    record=permit.consume('release',cap,context)
    require(record=={'gateSha256':sha(canonical(gate))}, 'native.release_gate_changed')
    return True


def require_custody_permit(permit,cap,context,required_roles):
    require(type(permit) is _OneUsePermit and type(required_roles) in (set,frozenset,tuple,list)
            and all(type(x) is str for x in required_roles), 'native.custody_permit_unissued')
    record=permit.consume('custody',cap,context)
    require(type(record) is dict and set(required_roles)<=set(record), 'native.custody_roles')
    for row in record.values():
        require(type(row) is dict and set(row)=={'bytes','sha256'} and
                type(row['bytes']) is int and row['bytes']>=0 and
                type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),
                'native.custody_fact')
    if 'report' in record:
        require(record['report']=={'bytes':context['privacyBytes'],
                'sha256':context['privacySha256']}, 'native.custody_report_pin')
    return record


def synthetic_release_permit(cap,io,context,gate):
    require_capability(cap,'storage',io)
    return _OneUsePermit(_KEY,'release',cap,context,{'gateSha256':sha(canonical(gate))})


def synthetic_custody_permit(cap,io,context,roles):
    require_capability(cap,'storage',io)
    return _OneUsePermit(_KEY,'custody',cap,context,roles)


CANDIDATE_PERMIT_KEYS = frozenset(('schema','retainedConsumerProofSha256',
    'retainedContextSha256','manifestSha256','sourceSha','sourceTree','indexDigest',
    'imageDigest','configDigest','archiveSha256','inspectionToolingSha',
    'privacySha256','version','extensions'))


def _candidate_record(record):
    require(type(record) is dict and set(record)==CANDIDATE_PERMIT_KEYS and
            all(type(v) is str for v in record.values()) and
            record['schema']=='openclaw.retained-consumer-candidate-permit.v1',
            'native.candidate_record_schema')
    for key in ('retainedConsumerProofSha256','retainedContextSha256','manifestSha256',
                'archiveSha256','privacySha256'):
        require(re.fullmatch('[0-9a-f]{64}',record[key]),'native.candidate_record_digest')
    for key in ('sourceSha','sourceTree','inspectionToolingSha'):
        require(re.fullmatch('[0-9a-f]{40}',record[key]),'native.candidate_record_revision')
    for key in ('indexDigest','imageDigest','configDigest'):
        require(re.fullmatch('sha256:[0-9a-f]{64}',record[key]),'native.candidate_record_oci')
    require(re.fullmatch('[0-9]{4}\\.[0-9]{1,2}\\.[0-9]{1,2}',record['version']),
            'native.candidate_record_version')
    extensions=record['extensions'].split(',')
    require(2<=len(extensions)<=32 and len(set(extensions))==len(extensions) and
            {'codex','workboard'}<=set(extensions) and
            all(re.fullmatch('[a-z][a-z0-9-]{0,63}',x) for x in extensions),
            'native.candidate_record_extensions')
    return json.loads(canonical(record))


def require_candidate_permit(permit,cap,io):
    require_capability(cap,'candidate',io)
    require(type(permit) is _OneUsePermit,'native.candidate_permit_unissued')
    return _candidate_record(permit.consume('candidate',cap,cap.context))


def synthetic_candidate_permit(cap,io,record):
    require_capability(cap,'candidate',io)
    return _OneUsePermit(_KEY,'candidate',cap,cap.context,_candidate_record(record))


def issue_native_candidate_permit(cap,retained_pass,io):
    require_capability(cap,'candidate',io)
    require(cap.kind=='private-native','native.candidate_private_only')
    from consumer_acceptance import validate_retained_pass
    record=validate_retained_pass(retained_pass,cap.owner,cap.context)
    require(record['retainedContextSha256']==sha(canonical(cap.context)),
            'native.candidate_context')
    return _OneUsePermit(_KEY,'candidate',cap,cap.context,_candidate_record(record))


def _peer(cap,peer,bootstrap):
    import guest_bootstrap
    require(type(cap) is SessionCapability and cap._key is _KEY and
            cap.kind in ('private-native','ci-native-proof') and
            type(bootstrap) is guest_bootstrap.VerifiedBootstrap and
            type(peer) is guest_bootstrap.PeerAuthority and bootstrap.owner==cap.owner and
            bootstrap.bundle_sha256==cap.owner['guestSourceSha256'],
            'native.peer_unissued')
    peer.require_for(bootstrap,bootstrap.purpose,peer._channel)
    channel=peer._channel
    if cap.kind=='private-native':
        from framed_channel import NativeFramedChannel
        require(type(channel) is NativeFramedChannel,'native.private_peer_channel')
        receipt=channel.assert_for_bootstrap(bootstrap)
    else:
        receipt=channel
    require_authenticated_peer_channel(bootstrap._grant._cap,receipt,bootstrap.purpose)
    require_owner_guard(cap,cap._owner_guard)
    return channel


def _final_context(cap,context):
    initial=cap.context
    require(type(context) is dict and set(context)==set(initial) and
            all(context[k]==v for k,v in initial.items() if k not in
                ('inputManifestSha256','workerDeadlineUtc')) and
            initial.get('inputManifestSha256') is None and
            initial.get('workerDeadlineUtc') is None and
            type(context.get('inputManifestSha256')) is str and
            re.fullmatch('[0-9a-f]{64}',context['inputManifestSha256']) and
            utc(context['workerDeadlineUtc'])<utc(cap.owner['providerStopAt']),
            'native.final_context_join')


def issue_peer_release_permit(cap,peer,bootstrap,context,gate,snapshot_sha,ready_sha):
    _peer(cap,peer,bootstrap)
    _final_context(cap,context)
    require(all(type(v) is str and re.fullmatch('[0-9a-f]{64}',v) for v in
                (snapshot_sha,ready_sha)),'native.release_evidence_digest')
    # GuestServer has independently replayed the cached raw snapshot and ready
    # frame before this source-internal call. Untrusted RPC dispatch has no
    # constructor/issuer endpoint; worker cannot write the authenticated pipe.
    import worker
    import protocol
    worker.validate_gate(gate,context,sha(canonical(context)),
                         {k:gate.get(k) for k in ('pid','uid','gid')},protocol,
                         dt.datetime.now(dt.timezone.utc))
    return _OneUsePermit(_KEY,'release',cap,context,{'gateSha256':sha(canonical(gate))})


def issue_peer_custody_permit(cap,peer,bootstrap,context,roles,response_hashes):
    channel=_peer(cap,peer,bootstrap)
    _final_context(cap,context)
    require(callable(getattr(channel,'consume_custody_ack',None)),
            'native.mac_custody_ack_unissued')
    ack=channel.consume_custody_ack(cap.owner,sha(canonical(context)),roles,response_hashes)
    require(type(ack) is dict and ack.get('roles')==roles and
            type(ack.get('custodySha256')) is str and
            re.fullmatch('[0-9a-f]{64}',ack['custodySha256']),
            'native.mac_custody_ack_changed')
    return _OneUsePermit(_KEY,'custody',cap,context,roles)


def issue_private(*_args, **_kwargs):
    raise Refusal('native.private_issuer_not_implemented')


if __name__ == '__main__':
    raise SystemExit('native_authority_no_cli')
