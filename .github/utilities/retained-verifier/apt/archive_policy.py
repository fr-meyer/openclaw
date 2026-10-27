"""Public historical-fixture policy, not an execution or authentication grant.

Pure byte/status classification only. The CI owner must run recognized gpgv on
these exact bytes and bind the actual APT context before using this result.
No process, package manager, network, key import or settings change occurs here.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import re


class Refusal(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise Refusal(reason)


@dataclass(frozen=True)
class Fixture:
    release_sha256: str
    release_bytes: int
    packages_sha256: str
    packages_bytes: int
    date: str
    version: str
    primaries: frozenset


BOOKWORM = Fixture(
    '77737fa4b34f2693e982cc9ee35736816c35a7778fc2d326cc1bbf5b301fe1aa',
    151075,
    '515e692f2c4121c6fcec444ef100cc18f79a991910615f3a88c8b7becfc94d2f',
    50060337,
    'Sat, 11 Jul 2026 10:16:37 UTC',
    '12.15',
    frozenset(('B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8',
               '4D64FEC119C2029067D6E791F8D2585B8783D481')),
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def signed_body(raw):
    require(type(raw) is bytes and len(raw) <= 196608, 'release_size')
    require(b'\r' not in raw and b'\x00' not in raw, 'release_encoding')
    try:
        text = raw.decode('ascii')
    except UnicodeError:
        raise Refusal('release_encoding') from None
    require(text.startswith('-----BEGIN PGP SIGNED MESSAGE-----\n'), 'not_clearsigned')
    split = text.find('\n\n')
    end = text.find('\n-----BEGIN PGP SIGNATURE-----\n')
    require(split > 0 and end > split and
            text.count('-----BEGIN PGP SIGNATURE-----') == 1 and
            text.rstrip().endswith('-----END PGP SIGNATURE-----'), 'clearsign_shape')
    require(all(line.startswith('Hash: ') for line in text[:split].splitlines()[1:]),
            'clearsign_header')
    # RFC4880 dash escaping. The body is parsed only after caller-supplied
    # exact-byte/signature outcome checks; it never authenticates itself.
    return '\n'.join(line[2:] if line.startswith('- ') else line
                     for line in text[split + 2:end].splitlines())


def fields(body):
    result = {}
    current = None
    for line in body.splitlines():
        if line.startswith((' ', '\t')):
            require(current is not None, 'orphan_continuation')
            result[current].append(line.strip())
            continue
        require(': ' in line or line.endswith(':'), 'field_syntax')
        key, value = line.split(':', 1)
        require(re.fullmatch(r'[A-Za-z][A-Za-z0-9-]*', key) is not None and
                key not in result, 'field_duplicate_or_name')
        result[key] = [value.strip()]
        current = key
    return result


def one(values, key):
    require(key in values and len(values[key]) == 1, 'field_' + key.lower())
    return values[key][0]


def signature_contract(returncode, timed_out, status, fixture=BOOKWORM):
    """Classify fresh fixed-process output; arbitrary JSON is not native proof."""
    require(timed_out is False and type(returncode) is int and returncode in (0, 2),
            'gpgv_exit')
    require(type(status) is bytes and len(status) <= 16384, 'gpgv_status_size')
    try:
        lines = status.decode('ascii').splitlines()
    except UnicodeError:
        raise Refusal('gpgv_status_encoding') from None
    valid = set()
    missing = []
    bad = {'BADSIG', 'REVKEYSIG', 'EXPKEYSIG', 'EXPSIG',
           'KEYEXPIRED', 'SIGEXPIRED', 'FAILURE', 'ERROR', 'NODATA'}
    for line in lines:
        require(line.startswith('[GNUPG:] '), 'gpgv_status_prefix')
        parts = line[9:].split()
        require(parts and parts[0] not in bad, 'gpgv_bad_status')
        if returncode == 2:
            require(parts[0] in {'NEWSIG','KEY_CONSIDERED','SIG_ID','GOODSIG','VALIDSIG',
                                 'ERRSIG','NO_PUBKEY'}, 'gpgv_unexpected_status')
        if parts[0] in ('ERRSIG', 'NO_PUBKEY'):
            missing.append(line)
            continue
        if parts[0] != 'VALIDSIG':
            continue
        require(len(parts) in (10, 11), 'gpgv_validsig_shape')
        signer = parts[1]
        primary = parts[10] if len(parts) == 11 else signer
        require(re.fullmatch('[0-9A-F]{40}', signer) is not None and
                re.fullmatch('[0-9A-F]{40}', primary) is not None,
                'gpgv_fingerprint')
        require(primary not in valid, 'gpgv_duplicate_validsig')
        valid.add(primary)
    if returncode == 2:
        # This exact pinned Bookworm fixture has two trusted signatures and
        # one additional signature absent from Noble's Debian keyring. The
        # unknown signature is never used as authority.
        require(fixture == BOOKWORM and valid == fixture.primaries and missing == [
            '[GNUPG:] ERRSIG 78DBA3BC47EF2265 1 8 01 1783765032 9 B8E5F13176D2A7A75220028078DBA3BC47EF2265',
            '[GNUPG:] NO_PUBKEY 78DBA3BC47EF2265',
        ], 'gpgv_unexpected_cosignature')
    else:
        require(not missing, 'gpgv_bad_status')
    require(bool(valid & fixture.primaries), 'gpgv_expected_primary_absent')
    return sorted(valid)


def classify(release, packages, *, returncode, timed_out, status, checked_at,
             fixture=BOOKWORM):
    require(type(release) is bytes and len(release) == fixture.release_bytes and
            sha(release) == fixture.release_sha256, 'release_pin')
    require(type(packages) is bytes and len(packages) == fixture.packages_bytes and
            len(packages) <= 64 * 1024 * 1024 and
            sha(packages) == fixture.packages_sha256, 'packages_pin')
    require(isinstance(checked_at, datetime) and checked_at.tzinfo is not None and
            checked_at.utcoffset().total_seconds() == 0, 'check_time')
    primaries = signature_contract(returncode, timed_out, status, fixture)
    values = fields(signed_body(release))
    require(one(values, 'Origin') == 'Debian' and
            one(values, 'Codename') == 'bookworm' and
            one(values, 'Version') == fixture.version, 'distribution')
    date = one(values, 'Date')
    require(date == fixture.date, 'release_date_pin')
    try:
        released = datetime.strptime(date, '%a, %d %b %Y %H:%M:%S UTC').replace(tzinfo=timezone.utc)
        until = None if 'Valid-Until' not in values else datetime.strptime(
            one(values, 'Valid-Until'), '%a, %d %b %Y %H:%M:%S UTC').replace(tzinfo=timezone.utc)
    except ValueError:
        raise Refusal('release_date_format') from None
    require(released <= checked_at and (until is None or checked_at <= until),
            'release_time')
    require('SHA256' in values, 'sha256_field')
    entries = {}
    for line in values['SHA256']:
        if not line:
            continue
        parts = line.split()
        require(len(parts) == 3 and re.fullmatch('[0-9a-f]{64}', parts[0]) is not None and
                re.fullmatch('[0-9]+', parts[1]) is not None and parts[2] not in entries,
                'sha256_entry')
        entries[parts[2]] = (parts[0], int(parts[1]))
    require(entries.get('main/binary-amd64/Packages') ==
            (fixture.packages_sha256, fixture.packages_bytes), 'signed_packages_entry')
    return {'schema': 'public-archive-fixture-contract.v1',
            'classification': 'exact_historical_fixture_contract_matches',
            'nativeAuthenticationIssued': False,
            'freshSecurityUpdateBase': False,
            'releaseSha256': fixture.release_sha256,
            'packagesSha256': fixture.packages_sha256,
            'releaseDate': date, 'verifiedPrimaryFingerprints': primaries}


if __name__ == '__main__':
    raise SystemExit('disarmed_requires_reviewed_ci_native_verifier')
