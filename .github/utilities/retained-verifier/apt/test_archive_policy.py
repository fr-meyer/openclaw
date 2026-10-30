"""Synthetic process-output contracts; no GPG/APT/native authentication runs."""
import copy
from datetime import datetime, timezone
import unittest
from archive_policy import BOOKWORM, Fixture, Refusal, classify, fields, signature_contract, sha


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.packages = b'Package: synthetic\nVersion: 1\n\n'
        self.date = 'Sat, 11 Jul 2026 10:16:37 UTC'
        self.now = datetime(2026, 10, 27, tzinfo=timezone.utc)
        self.primary = 'B' * 40
        self.status = (f'[GNUPG:] NEWSIG\n[GNUPG:] VALIDSIG {"A" * 40} '
                       f'2026-07-11 1783764997 0 4 0 1 8 01 {self.primary}\n').encode()
        self.release = self.make_release()
        self.policy = self.make_policy(self.release)

    def make_release(self, *, date=None, valid_until=None, extra=''):
        body = ('Origin: Debian\nVersion: 12.15\nCodename: bookworm\n'
                f'Date: {date or self.date}\n')
        if valid_until:
            body += 'Valid-Until: ' + valid_until + '\n'
        body += ('SHA256:\n ' + sha(self.packages) + ' ' + str(len(self.packages)) +
                 ' main/binary-amd64/Packages\n' + extra)
        return ('-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n' + body +
                '-----BEGIN PGP SIGNATURE-----\nSYNTHETIC-NOT-A-SIGNATURE\n'
                '-----END PGP SIGNATURE-----\n').encode()

    def make_policy(self, raw, *, date=None):
        return Fixture(sha(raw), len(raw), sha(self.packages), len(self.packages),
                       date or self.date, '12.15', frozenset((self.primary,)))

    def check(self, **kw):
        args = dict(returncode=0, timed_out=False, status=self.status,
                    checked_at=self.now, fixture=self.policy)
        args.update(kw)
        return classify(self.release, self.packages, **args)

    def test_synthetic_match_never_issues_native_authentication_or_freshness(self):
        got = self.check()
        self.assertEqual(got['classification'], 'exact_historical_fixture_contract_matches')
        self.assertIs(got['nativeAuthenticationIssued'], False)
        self.assertIs(got['freshSecurityUpdateBase'], False)

    def test_timeout_even_with_complete_valid_status_refuses(self):
        with self.assertRaisesRegex(Refusal, 'gpgv_exit'):
            self.check(timed_out=True)

    def test_nonzero_none_bool_exit_refuses(self):
        for code in (1, None, False):
            with self.subTest(code=code), self.assertRaisesRegex(Refusal, 'gpgv_exit'):
                self.check(returncode=code)
        with self.assertRaisesRegex(Refusal,'gpgv_unexpected_cosignature'):
            self.check(returncode=2)

    def test_exact_bookworm_cosignature_requires_both_trusted_signatures(self):
        bookworm,release=sorted(BOOKWORM.primaries)
        status=(f'[GNUPG:] NEWSIG\n'
                f'[GNUPG:] VALIDSIG {bookworm} 2026-07-11 1783765031 0 4 0 1 8 01 {bookworm}\n'
                f'[GNUPG:] NEWSIG\n'
                f'[GNUPG:] ERRSIG 78DBA3BC47EF2265 1 8 01 1783765032 9 B8E5F13176D2A7A75220028078DBA3BC47EF2265\n'
                f'[GNUPG:] NO_PUBKEY 78DBA3BC47EF2265\n'
                f'[GNUPG:] NEWSIG\n'
                f'[GNUPG:] VALIDSIG {release} 2026-07-11 1783765141 0 4 0 22 8 01 {release}\n').encode()
        self.assertEqual(set(signature_contract(2,False,status,BOOKWORM)),BOOKWORM.primaries)
        for changed in (status.replace(b'1783765032',b'1783765033'),
                        status.replace(b'NO_PUBKEY 78DBA3BC47EF2265',b'NO_PUBKEY 0000000000000000'),
                        status.replace(b'ERRSIG',b'BADSIG'),
                        status.replace(bookworm.encode(),b'0'*40),
                        status.replace(b'NO_PUBKEY 78DBA3BC47EF2265\n',b''),
                        status+b'[GNUPG:] UNEXPECTED extra\n'):
            with self.subTest(changed=changed[-100:]),self.assertRaises(Refusal):
                signature_contract(2,False,changed,BOOKWORM)
        with self.assertRaises(Refusal):signature_contract(0,False,status,BOOKWORM)
        with self.assertRaises(Refusal):signature_contract(2,False,status,self.policy)

    def test_goodsig_only_is_not_validsig(self):
        with self.assertRaisesRegex(Refusal, 'expected_primary_absent'):
            self.check(status=b'[GNUPG:] GOODSIG ABCD Test\n')

    def test_wrong_primary_refuses(self):
        with self.assertRaisesRegex(Refusal, 'expected_primary_absent'):
            self.check(status=self.status.replace(self.primary.encode(), b'C' * 40))

    def test_bad_unknown_revoked_expired_statuses_refuse(self):
        for bad in ('BADSIG','ERRSIG','NO_PUBKEY','REVKEYSIG','EXPKEYSIG','EXPSIG',
                    'KEYEXPIRED','SIGEXPIRED','FAILURE','ERROR','NODATA'):
            with self.subTest(bad=bad), self.assertRaisesRegex(Refusal, 'bad_status'):
                self.check(status=self.status + ('[GNUPG:] ' + bad + '\n').encode())

    def test_duplicate_validsig_refuses(self):
        with self.assertRaisesRegex(Refusal, 'duplicate_validsig'):
            self.check(status=self.status * 2)

    def test_malformed_raw_status_refuses(self):
        for raw in (b'VALIDSIG A', b'\xff', b'[GNUPG:] VALIDSIG short\n', b'x' * 16385):
            with self.subTest(raw=raw[:20]), self.assertRaises(Refusal):
                self.check(status=raw)

    def test_release_or_index_changed_refuses(self):
        with self.assertRaisesRegex(Refusal, 'release_pin'):
            classify(self.release + b' ', self.packages, returncode=0, timed_out=False,
                     status=self.status, checked_at=self.now, fixture=self.policy)
        with self.assertRaisesRegex(Refusal, 'packages_pin'):
            classify(self.release, self.packages + b' ', returncode=0, timed_out=False,
                     status=self.status, checked_at=self.now, fixture=self.policy)

    def test_duplicate_core_field_even_when_rehashed_refuses(self):
        self.release = self.make_release(extra='Origin: Debian\n')
        self.policy = self.make_policy(self.release)
        with self.assertRaisesRegex(Refusal, 'duplicate_or_name'):
            self.check()

    def test_signed_index_size_or_hash_mismatch_even_rehashed_refuses(self):
        self.release = self.make_release().replace(sha(self.packages).encode(), b'0' * 64)
        self.policy = self.make_policy(self.release)
        with self.assertRaisesRegex(Refusal, 'signed_packages_entry'):
            self.check()

    def test_wrong_distribution_even_when_rehashed_refuses(self):
        self.release = self.make_release().replace(b'Codename: bookworm', b'Codename: trixie')
        self.policy = self.make_policy(self.release)
        with self.assertRaisesRegex(Refusal, 'distribution'):
            self.check()

    def test_expired_valid_until_even_when_rehashed_refuses(self):
        self.release = self.make_release(valid_until='Sun, 12 Jul 2026 10:16:37 UTC')
        self.policy = self.make_policy(self.release)
        with self.assertRaisesRegex(Refusal, 'release_time'):
            self.check()

    def test_future_signed_date_and_naive_check_clock_refuse(self):
        date = 'Wed, 11 Nov 2026 10:16:37 UTC'
        self.release = self.make_release(date=date)
        self.policy = self.make_policy(self.release, date=date)
        with self.assertRaisesRegex(Refusal, 'release_time'):
            self.check()
        with self.assertRaisesRegex(Refusal, 'check_time'):
            self.check(checked_at=datetime(2026,10,27))

    def test_wrong_pinned_date_even_rehashed_refuses(self):
        self.release = self.make_release(date='Sun, 12 Jul 2026 10:16:37 UTC')
        self.policy = self.make_policy(self.release)
        with self.assertRaisesRegex(Refusal, 'release_date_pin'):
            self.check()

    def test_duplicate_signed_sha_row_refuses(self):
        row = ' ' + sha(self.packages) + ' ' + str(len(self.packages)) + ' main/binary-amd64/Packages\n'
        self.release = self.make_release(extra=row)
        self.policy = self.make_policy(self.release)
        with self.assertRaisesRegex(Refusal, 'sha256_entry'):
            self.check()


def security_fixture(packages=None, *, date='Sun, 25 Oct 2026 03:50:50 UTC',
                     until='Sun, 01 Nov 2026 03:50:50 UTC'):
    import archive_policy as p
    if packages is None:
        packages=''.join('Package: '+name+'\nVersion: '+p.PYTHON_U9_VERSION+
            '\nArchitecture: amd64\nFilename: '+filename+'\nSize: '+str(size)+
            '\nSHA256: '+digest+'\n\n' for name,(size,digest,filename) in p.PYTHON_U9.items()).encode()
    body=('Origin: Debian\nLabel: Debian-Security\nSuite: oldstable-security\nVersion: 12\n'
          'Codename: bookworm-security\nDate: '+date+'\nValid-Until: '+until+'\nSHA256:\n '+
          p.sha(packages)+' '+str(len(packages))+' main/binary-amd64/Packages\n')
    release=('-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n'+body+
             '-----BEGIN PGP SIGNATURE-----\nSYNTHETIC-NOT-A-SIGNATURE\n-----END PGP SIGNATURE-----\n').encode()
    primary=next(iter(p.SECURITY_PRIMARIES))
    status=('[GNUPG:] VALIDSIG '+primary+' 2026-10-25 1792899000 0 4 0 1 8 01 '+primary+'\n').encode()
    return release,packages,status


def extra_valid_security_signature(status, primary='C'*40):
    """Synthetic successful co-signature, never an actual release signer claim."""
    return status+('[GNUPG:] VALIDSIG '+primary+' 2026-10-25 1792899000 0 4 0 1 8 01 '+primary+'\n').encode()


class SecurityPolicyTests(unittest.TestCase):
    def setUp(self):
        import archive_policy as p
        self.p=p;self.release,self.packages,self.status=security_fixture()
        self.now=datetime(2026,10,30,tzinfo=timezone.utc)
    def check(self,**kw):
        args=dict(returncode=0,timed_out=False,status=self.status,checked_at=self.now);args.update(kw)
        return self.p.classify_security(self.release,self.packages,**args)
    def test_independent_security_signature_hash_time_and_no_authority(self):
        value=self.check();self.assertEqual(value['packagesSha256'],sha(self.packages))
        self.assertEqual(value['verifiedPrimaryFingerprints'],sorted(self.p.SECURITY_PRIMARIES))
        self.assertIs(value['nativeAuthenticationIssued'],False)
    def test_main_signer_and_its_unknown_cosignature_exception_are_never_security_authority(self):
        main=next(iter(BOOKWORM.primaries)).encode()
        for status in (self.status.replace(next(iter(self.p.SECURITY_PRIMARIES)).encode(),main),
                       self.status+b'[GNUPG:] NO_PUBKEY 78DBA3BC47EF2265\n',self.status*2):
            with self.subTest(status=status[:40]),self.assertRaises(Refusal):self.check(status=status)
        for value in (2,1,False,None):
            with self.subTest(value=value),self.assertRaises(Refusal):self.check(returncode=value)
    def test_security_distribution_label_codename_version_and_exact_index(self):
        for old,new in ((b'Debian-Security',b'Debian'),(b'bookworm-security',b'bookworm'),
                        (b'Version: 12\n',b'Version: 13\n'),
                        (b'main/binary-amd64/Packages',b'updates/main/binary-amd64/Packages')):
            original=self.release;self.release=original.replace(old,new)
            with self.subTest(old=old),self.assertRaises(Refusal):self.check()
            self.release=original
    def test_security_requires_both_signed_dates_and_current_time(self):
        for when in (datetime(2026,10,24,tzinfo=timezone.utc),datetime(2026,11,2,tzinfo=timezone.utc)):
            with self.subTest(when=when),self.assertRaises(Refusal):self.check(checked_at=when)
        self.release=self.release.replace(b'Valid-Until:',b'Other-Until:')
        with self.assertRaises(Refusal):self.check()
    def test_security_changed_index_duplicate_field_and_truncated_status_refuse(self):
        self.packages+=b'changed'
        with self.assertRaises(Refusal):self.check()
        self.release,self.packages,self.status=security_fixture()
        self.release=self.release.replace(b'Origin: Debian\n',b'Origin: Debian\nOrigin: Debian\n')
        with self.assertRaises(Refusal):self.check()
        self.release,self.packages,self.status=security_fixture()
        for status in (b'',self.status[:30],b'x'*16385):
            with self.subTest(status=status[:30]),self.assertRaises(Refusal):self.check(status=status)


    def test_required_plus_successful_extra_signatures_preserve_full_sorted_provenance(self):
        status=extra_valid_security_signature(self.status)
        got=self.check(status=status)
        self.assertEqual(got['verifiedPrimaryFingerprints'],sorted(set(self.p.SECURITY_PRIMARIES)|{'C'*40}))
        self.assertFalse(got['nativeAuthenticationIssued'])
        self.assertTrue(self.p.security_primary_roster_ok(got['verifiedPrimaryFingerprints']))
        with self.assertRaisesRegex(Refusal,'security_gpgv_primary'):
            self.check(status=extra_valid_security_signature(b''))
    def test_successful_extra_signatures_never_override_bad_or_unknown_status_or_exit(self):
        status=extra_valid_security_signature(self.status)
        for token in ('BADSIG','EXPSIG','REVKEYSIG','ERRSIG','NO_PUBKEY','EXPKEYSIG','KEYEXPIRED',
                      'SIGEXPIRED','FAILURE','ERROR','NODATA','UNEXPECTED'):
            with self.subTest(token=token),self.assertRaisesRegex(Refusal,'security_gpgv_status'):
                self.check(status=status+('[GNUPG:] '+token+'\n').encode())
        for code in (2,1,False,None):
            with self.subTest(code=code),self.assertRaises(Refusal):self.check(status=status,returncode=code)
        with self.assertRaises(Refusal):self.check(status=status,timed_out=True)
        for invalid in (status+self.status,b'x'*16385,status+b'[GNUPG:] VALIDSIG short\n',b'\xff'):
            with self.subTest(invalid=invalid[:30]),self.assertRaises(Refusal):self.check(status=invalid)
    def test_primary_roster_is_exact_sorted_unique_bounded_hex_and_required(self):
        required=sorted(self.p.SECURITY_PRIMARIES)
        for value in (None,set(required),[],['C'*40],required*2,required+[True],
                      required+['c'*40],list(reversed(required+['C'*40])),required+['short']):
            with self.subTest(value=value):self.assertFalse(self.p.security_primary_roster_ok(value))
        self.assertFalse(self.p.security_primary_roster_ok([f'{i:040X}'for i in range(410)]))
    def test_signer_failure_projection_is_bounded_public_hex_only_and_not_authority(self):
        import json
        status=self.status+b'[GNUPG:] GOODSIG ABCD PRIVATE_UID_NOT_EXPORTED\n'
        for index in range(12):status=extra_valid_security_signature(status,f'{index:040X}')
        facts=self.p.security_signature_evidence(status)
        self.assertTrue(facts['statusParsed']);self.assertTrue(facts['requiredPrimaryPresent'])
        self.assertEqual(facts['verifiedPrimaryCount'],13);self.assertEqual(len(facts['verifiedPrimaryFingerprints']),8)
        self.assertTrue(facts['fingerprintsTruncated']);self.assertFalse(facts['newAuthenticationAuthority'])
        raw=json.dumps(facts,sort_keys=True,separators=(',',':')).encode()
        self.assertLessEqual(len(raw),1024);self.assertNotIn(b'PRIVATE_UID',raw)
        self.assertEqual(facts['statusSha256'],sha(status));self.assertEqual(facts['statusBytes'],len(status))
        missing=self.p.security_signature_evidence(extra_valid_security_signature(b''))
        self.assertTrue(missing['statusParsed']);self.assertFalse(missing['requiredPrimaryPresent'])
        malformed=self.p.security_signature_evidence(status+b'[GNUPG:] NO_PUBKEY private value\n')
        self.assertFalse(malformed['statusParsed']);self.assertEqual(malformed['verifiedPrimaryFingerprints'],[])
        self.assertNotIn('private value',repr(malformed))


if __name__ == '__main__':
    unittest.main()
