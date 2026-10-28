"""Single owned, deadline-bounded guest stdin/stdout frame channel.

Frames are eight uppercase ASCII hexadecimal length bytes, a newline, then
canonical JSON. No constructor opens a route or accepts a path. The native
factory requires a verified bootstrap and the already authenticated outer
peer receipt, and binds only descriptors 0 and 1 in one process.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import selectors
import stat

import durable_intent
import guest_bootstrap
from protocol import Refusal, canonical, decode, require, utc

_KEY = object()
HEADER = 9
MAX_REQUEST = 65536
MAX_RESPONSE = 3 * 1024 * 1024
ACK_CAP = 16384
ACK_SCHEMA = 'openclaw.private-mac-custody-ack.v1'
_HEX = re.compile('[0-9a-f]{64}\\Z')


def _deadline(value):
    if type(value) is str: value = utc(value)
    require(type(value) is dt.datetime and value.tzinfo is not None,
            'framed.deadline')
    remaining = (value-dt.datetime.now(dt.timezone.utc)).total_seconds()
    require(remaining > 0, 'framed.deadline')
    return remaining


class NativeFramedChannel:
    __slots__ = ('_key','_bootstrap','_receipt','_input','_output',
                 '_source_input','_source_output','_input_identity',
                 '_output_identity','_closed',
                 '_synthetic','_blocked','_read_count','_write_count',
                 '_ack','_ack_used','nonreconnecting')
    def __setattr__(self,name,value):
        require(not hasattr(self,name) or name in
                ('_blocked','_read_count','_write_count','_ack','_ack_used',
                 '_closed'),
                'framed.immutable')
        object.__setattr__(self,name,value)
    def __delattr__(self,_name):
        raise Refusal('framed.immutable')
    def __init__(self,key,bootstrap,receipt,input_fd,output_fd,synthetic):
        require(key is _KEY and type(bootstrap) is
                guest_bootstrap.VerifiedBootstrap and
                type(input_fd) is int and type(output_fd) is int and
                input_fd != output_fd,'framed.unissued')
        if synthetic:
            require(bootstrap.purpose == 'synthetic-contract',
                    'framed.synthetic_only')
        else:
            require(bootstrap.purpose in ('private-owned-ssh','ci-native-proof') and
                    input_fd == 0 and output_fd == 1 and
                    receipt is bootstrap._grant._channel_receipt and
                    os.geteuid() == 0,'framed.native_peer')
        identities=[]
        for fd in (input_fd,output_fd):
            info=os.fstat(fd)
            require(stat.S_ISFIFO(info.st_mode) or stat.S_ISSOCK(info.st_mode),
                    'framed.descriptor_type')
            identities.append((info.st_dev,info.st_ino,info.st_mode,
                               info.st_uid,info.st_gid,info.st_rdev))
        self._key,self._bootstrap,self._receipt=key,bootstrap,receipt
        self._source_input,self._source_output=input_fd,output_fd
        self._input_identity,self._output_identity=identities
        self._input,self._output=os.dup(input_fd),os.dup(output_fd)
        self._synthetic,self._blocked=synthetic,False
        self._closed=False
        self._read_count=self._write_count=0
        self._ack=None;self._ack_used=False
        self.nonreconnecting=True
        os.set_blocking(self._input,False)
        os.set_blocking(self._output,False)

    @staticmethod
    def _identity(fd):
        info=os.fstat(fd)
        return (info.st_dev,info.st_ino,info.st_mode,
                info.st_uid,info.st_gid,info.st_rdev)

    def _assert_descriptors(self):
        try:
            require(not self._closed and
                    self._identity(self._source_input) ==
                        self._identity(self._input) == self._input_identity and
                    self._identity(self._source_output) ==
                        self._identity(self._output) == self._output_identity,
                    'framed.descriptor_changed')
        except OSError:
            raise Refusal('framed.descriptor_changed') from None

    def close(self):
        if not self._closed:
            self._closed=True;self._blocked=True
            os.close(self._input);os.close(self._output)

    def assert_for_bootstrap(self,bootstrap):
        require(type(self) is NativeFramedChannel and self._key is _KEY and
                self._bootstrap is bootstrap and not self._blocked and
                not self._synthetic,'framed.peer_changed')
        self._assert_descriptors()
        bootstrap.assert_source_path()
        return self._receipt

    @property
    def read_count(self):return self._read_count
    @property
    def write_count(self):return self._write_count

    def _ready(self,fd,event,deadline_utc):
        self._assert_descriptors()
        with selectors.DefaultSelector() as selector:
            selector.register(fd,event)
            require(selector.select(_deadline(deadline_utc)),
                    'framed.timeout')
        self._assert_descriptors()

    def _read_exact(self,count,deadline_utc):
        parts=[];total=0
        while total<count:
            self._ready(self._input,selectors.EVENT_READ,deadline_utc)
            try:raw=os.read(self._input,count-total)
            except BlockingIOError:continue
            require(raw,'framed.eof')
            parts.append(raw);total+=len(raw)
        return b''.join(parts)

    def _payload(self,max_bytes,deadline_utc):
        header=self._read_exact(HEADER,deadline_utc)
        require(header[8:] == b'\n' and all(c in b'0123456789ABCDEF'
                for c in header[:8]),'framed.header')
        size=int(header[:8],16)
        require(0<size<=max_bytes,'framed.request_cap')
        return self._read_exact(size,deadline_utc)

    def _accept_ack(self,value,raw):
        require(self._ack is None and not self._ack_used and
                15 <= self._write_count < 32 and
                len(raw) <= ACK_CAP and
                type(value) is dict and set(value) ==
                {'schema','owner','contextSha256','roles','responses',
                 'custodySha256'} and
                value['schema'] == ACK_SCHEMA and
                value['owner'] == self._bootstrap.owner and
                type(value['contextSha256']) is str and
                _HEX.fullmatch(value['contextSha256']) is not None and
                type(value['custodySha256']) is str and
                _HEX.fullmatch(value['custodySha256']) is not None,
                'framed.ack_header')
        roles=value['roles']
        require(type(roles) is dict and
                set(roles)==durable_intent.REQUIRED_CUSTODY,
                'framed.ack_roles')
        for role,row in roles.items():
            require(type(row) is dict and set(row)=={'bytes','sha256'} and
                    type(row['bytes']) is int and
                    0<=row['bytes']<=durable_intent.EVIDENCE_CAPS[role] and
                    type(row['sha256']) is str and
                    _HEX.fullmatch(row['sha256']) is not None,
                    'framed.ack_role_row')
        responses=value['responses']
        require(type(responses) is list and len(responses)==self._write_count and
                all(type(row) is dict and set(row)=={'sequence','sha256'} and
                    type(row['sequence']) is int and row['sequence']==index and
                    type(row['sha256']) is str and
                    _HEX.fullmatch(row['sha256']) is not None
                    for index,row in enumerate(responses)),
                'framed.ack_responses')
        self._ack=canonical(value)

    def read_frame_once(self,max_bytes,deadline_utc):
        require(not self._blocked and type(max_bytes) is int and
                0 < max_bytes <= MAX_REQUEST and
                self._read_count == self._write_count,
                'framed.read_order')
        try:
            raw=self._payload(max_bytes,deadline_utc)
            value=decode(raw,max_bytes)
            require(canonical(value)==raw,'framed.json_canonical')
            if type(value) is dict and value.get('schema')==ACK_SCHEMA:
                self._accept_ack(value,raw)
                raw=self._payload(max_bytes,deadline_utc)
                value=decode(raw,max_bytes)
                require(canonical(value)==raw and
                        type(value) is dict and
                        value.get('schema') ==
                            'openclaw.private-guest-request.v1' and
                        value.get('method') ==
                            'remove_only_copied_session_files_after_custody' and
                        value.get('owner') == self._bootstrap.owner and
                        type(value.get('sequence')) is int and
                        value['sequence'] == self._write_count and
                        value.get('arguments') == [],
                        'framed.ack_double_or_request')
            self._read_count+=1
            return raw
        except BaseException:
            self._blocked=True
            raise Refusal('framed.read_uncertain') from None

    def consume_custody_ack(self,owner,context_sha256,rows,response_hashes):
        """One typed peer receipt; the root permit issuer still checks Mac fsync."""
        require(not self._blocked and self._ack is not None and
                not self._ack_used and
                self._read_count == self._write_count+1,
                'framed.ack_unissued')
        self._assert_descriptors()
        self._ack_used=True  # Failed comparison cannot retry with changed rows.
        ack=decode(self._ack,ACK_CAP)
        expected_responses=[{'sequence':seq,'sha256':response_hashes[seq]}
                            for seq in range(len(response_hashes))]
        require(ack['owner']==owner and
                ack['contextSha256']==context_sha256 and
                ack['roles']==rows and
                ack['responses']==expected_responses,
                'framed.ack_changed')
        return {'custodySha256':ack['custodySha256'],
                'roles':json.loads(canonical(rows)),
                'responses':expected_responses}

    def write_frame_once(self,raw,deadline_utc):
        require(not self._blocked and type(raw) is bytes and
                0<len(raw)<=MAX_RESPONSE and
                self._read_count == self._write_count+1,
                'framed.write_order')
        frame=f'{len(raw):08X}\n'.encode('ascii')+raw
        remaining=memoryview(frame)
        try:
            while remaining:
                self._ready(self._output,selectors.EVENT_WRITE,deadline_utc)
                try:count=os.write(self._output,remaining)
                except BlockingIOError:continue
                require(count>0,'framed.short_write')
                remaining=remaining[count:]
            self._write_count+=1
        except BaseException:
            self._blocked=True
            raise Refusal('framed.write_uncertain') from None


def issue_from_verified_bootstrap(bootstrap,receipt,*,input_fd=0,output_fd=1):
    require(type(bootstrap) is guest_bootstrap.VerifiedBootstrap and
            bootstrap.purpose in ('private-owned-ssh','ci-native-proof') and
            receipt is bootstrap._grant._channel_receipt,
            'framed.source_peer_unissued')
    bootstrap.assert_source_path()
    return NativeFramedChannel(_KEY,bootstrap,receipt,input_fd,output_fd,False)


def synthetic_channel_for_test(bootstrap,input_fd,output_fd):
    require(type(bootstrap) is guest_bootstrap.VerifiedBootstrap and
            bootstrap.purpose == 'synthetic-contract',
            'framed.synthetic_only')
    return NativeFramedChannel(_KEY,bootstrap,None,input_fd,output_fd,True)


if __name__=='__main__':raise SystemExit('framed_channel_no_cli')
