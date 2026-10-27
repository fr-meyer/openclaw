"""Synthetic guest signature admission tests; no GPG process or key import."""
import unittest

from ci_archive_policy import BOOKWORM, Fixture, Refusal, signature_contract


def status(*, extra=b'', include_second=True):
    first, second = sorted(BOOKWORM.primaries)
    lines = (
        f'[GNUPG:] NEWSIG\n'
        f'[GNUPG:] VALIDSIG {first} 2026-07-11 1783765031 0 4 0 1 8 01 {first}\n'
        f'[GNUPG:] NEWSIG\n'
        f'[GNUPG:] ERRSIG 78DBA3BC47EF2265 1 8 01 1783765032 9 B8E5F13176D2A7A75220028078DBA3BC47EF2265\n'
        f'[GNUPG:] NO_PUBKEY 78DBA3BC47EF2265\n'
        f'[GNUPG:] NEWSIG\n'
    ).encode()
    if include_second:
        lines += (f'[GNUPG:] VALIDSIG {second} 2026-07-11 '
                  f'1783765141 0 4 0 22 8 01 {second}\n').encode()
    return lines + extra


class GuestSignaturePolicyTests(unittest.TestCase):
    def test_exact_pinned_cosignature_preserves_both_trusted_signers(self):
        self.assertEqual(set(signature_contract(2, False, status())), BOOKWORM.primaries)

    def test_unknown_signer_never_becomes_authority(self):
        raw = status()
        for altered in (
            raw.replace(b'1783765032', b'1783765033'),
            raw.replace(b'NO_PUBKEY 78DBA3BC47EF2265', b'NO_PUBKEY 0000000000000000'),
            raw.replace(b'ERRSIG ', b'BADSIG '),
            raw.replace(b'NO_PUBKEY 78DBA3BC47EF2265\n', b''),
            raw + b'[GNUPG:] UNEXPECTED extra\n',
            status(include_second=False),
        ):
            with self.subTest(altered=altered[-96:]), self.assertRaises(Refusal):
                signature_contract(2, False, altered)

    def test_fixture_exit_and_timeout_binding(self):
        raw = status()
        other = Fixture(BOOKWORM.release_sha256, BOOKWORM.release_bytes,
                        BOOKWORM.packages_sha256, BOOKWORM.packages_bytes,
                        BOOKWORM.date, BOOKWORM.version, frozenset((sorted(BOOKWORM.primaries)[0],)))
        for code, timed_out, fixture in ((0, False, BOOKWORM), (1, False, BOOKWORM),
                                         (2, True, BOOKWORM), (2, False, other)):
            with self.subTest(code=code, timed_out=timed_out, fixture=fixture), self.assertRaises(Refusal):
                signature_contract(code, timed_out, raw, fixture)


if __name__ == '__main__':
    unittest.main()
