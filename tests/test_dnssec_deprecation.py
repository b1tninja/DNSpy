"""RFC 9905 and RFC 9906: the algorithms DNSSEC deprecated after RFC 9904 set the table.

RFC 9904 answers what a validator must be able to compute; these two November-2025
INTERNET STANDARDS answer what it may still believe. RFC 9905 §2 speaks in two
voices: a DS record naming RSASHA1 or RSASHA1-NSEC3-SHA1 is unconditionally to be
treated as insecure (¶1), while signatures those algorithms make are for the
*operator* to treat as unsupported by default, with the implementation MUST keep
the arithmetic behind them (¶2). RFC 9906 retires ECC-GOST in both slots without
that second voice at all. The tests below pin each sentence to the state it names:
SignatureOutcome.DEPRECATED distinct from 9904's UNSUPPORTED, ChainOutcome.INSECURE
distinct from BOGUS and INDETERMINATE, and the boundary of the opt-in ¶2's two
sentences jointly require.
"""

import pytest

from namespy import crypto
from namespy.crypto import (
    IMPLEMENT_FOR_VALIDATION,
    ValidationRequirement,
    crypto_available,
)
from namespy.dnssec import ds_digest, pack_rsa_public_key
from namespy.enums import DnsRType
from namespy.rdata import RData_A, RData_DNSKEY, RData_DS, RData_RRSIG
from namespy.validate import Validator
from namespy.verify import (
    ChainOutcome,
    SignatureOutcome,
    authenticate_dnskey_rrset,
    verify_rrsig,
)

OWNER = "example.net."
EXP, INC, NOW = 1440021600, 1438207200, 1440000000


def _needs_backend() -> None:
    if not crypto_available():
        pytest.skip("namespy[crypto] is not installed")


def _dnskey(algorithm: int, key, flags: int = 257, protocol: int = 3) -> RData_DNSKEY:
    return RData_DNSKEY(flags, protocol, algorithm, key)


def _rrsig(
    algorithm: int,
    tag: int,
    signature=b"\x01\x02",
    type_covered: int | None = None,
    signer: str = OWNER,
    labels: int = 3,
) -> RData_RRSIG:
    return RData_RRSIG(
        type_covered=int(DnsRType.A) if type_covered is None else type_covered,
        algorithm=algorithm,
        labels=labels,
        original_ttl=3600,
        expiration=EXP,
        inception=INC,
        key_tag=tag,
        signer_name=signer,
        signature=signature,
    )


def _a_rrset():
    return [RData_A("192.0.2.1")]


# ------------------------------------------------------------------------ the policy tables


def test_the_policy_sets_are_the_numbers_the_documents_name():
    """Four sets, two per document, and the documents name different fields on purpose.

    9905 speaks of the DNSKEY-algorithm side of both records (the DS's Algorithm
    octet copies the DNSKEY); 9906 speaks of GOST on both sides too, but on its
    DS slot the deciding octet is the DS's own Digest Type -- GOST R 34.11-94,
    digest type 3 as RFC 5933 §4¶1 denotes it.
    """
    assert crypto.DEPRECATED_SIGNATURE_ALGORITHMS == frozenset({5, 7})  # RFC 9905 §2¶2
    assert crypto.RETIRED_SIGNATURE_ALGORITHMS == frozenset({12})  # RFC 9906 §2¶2
    assert crypto.DEPRECATED_DS_ALGORITHMS == frozenset({5, 7})  # RFC 9905 §2¶1
    assert crypto.DEPRECATED_DS_DIGEST_TYPES == frozenset({3})  # RFC 9906 §2¶1

    # And the capability table stands untouched, as RFC 9905 §4¶2 says outright it
    # must: "this document is not changing" the Implement-for-validation column.
    assert IMPLEMENT_FOR_VALIDATION[5] is ValidationRequirement.MUST
    assert IMPLEMENT_FOR_VALIDATION[7] is ValidationRequirement.MUST


# ------------------------------------------------------------------- §2¶2: signature policy


@pytest.mark.parametrize("algorithm", [5, 7])
def test_deprecated_signatures_are_untrusted_by_default(algorithm: int):
    """The operator MUST that decides before the arithmetic does: §2¶2's "as unsupported"."""
    key = _dnskey(algorithm, b"\x01" * 32)
    verdict = verify_rrsig(
        _rrsig(algorithm, key.key_tag), "www.example.net.", _a_rrset(), [key], now=NOW
    )
    assert verdict.outcome is SignatureOutcome.DEPRECATED
    assert "RFC 9905 §2¶2" in verdict.reason


def test_gost_signatures_are_deprecated_with_no_way_back():
    """RFC 9906 §2¶2 has no continue-to-support sentence, so no opt-in opens it either."""
    key = _dnskey(12, b"\x01" * 32)
    for allow in (False, True):
        verdict = verify_rrsig(
            _rrsig(12, key.key_tag),
            "www.example.net.",
            _a_rrset(),
            [key],
            now=NOW,
            allow_deprecated_sha1=allow,
        )
        assert verdict.outcome is SignatureOutcome.DEPRECATED
        assert "RFC 9906 §2¶2" in verdict.reason


def test_the_capability_rfc_9905_requires_is_kept_behind_the_named_opt_in():
    """The gate opens on request, and what comes through is an arithmetic answer, not a policy one.

    A forged signature under a real-shaped 1024-bit RSA key must reach the crypto and
    be *refused* -- INVALID, with an attempt counted -- because §2¶2's second sentence
    ("Validating resolver implementations MUST continue to support validation using
    these algorithms") is about exactly this: the bytes get their check when the
    operator asks for it. The same bytes default to DEPRECATED, which is what keeps
    the two outcomes worth two enum members.
    """
    _needs_backend()
    key = _dnskey(7, pack_rsa_public_key(65537, int("f" * 256, 16)))  # 1024-bit modulus
    rrsig = _rrsig(7, key.key_tag, signature=b"\x01" * 128)
    default = verify_rrsig(rrsig, "www.example.net.", _a_rrset(), [key], now=NOW)
    assert default.outcome is SignatureOutcome.DEPRECATED
    assert default.attempts == 0
    opted = verify_rrsig(
        rrsig, "www.example.net.", _a_rrset(), [key], now=NOW, allow_deprecated_sha1=True
    )
    assert opted.outcome is SignatureOutcome.INVALID
    assert opted.attempts == 1


# --------------------------------------------------------------------- §2¶1: DS policy


def test_a_sha1_ds_introduces_nothing_even_pointing_at_a_matching_key():
    """¶1 is unconditional: the DS never reaches its own digest arithmetic.

    The key underneath matches tag, algorithm, and digest exactly as §5.2¶5 would
    demand, and it still buys nothing -- "Operators of validating resolvers MUST
    treat RSASHA1 and RSASHA1-NSEC3-SHA1 DS records as insecure" leaves no digest
    loop to run. With nothing else as trust point, the link is not broken but
    void: ChainOutcome.INSECURE, the fourth name the documents added.
    """
    key = _dnskey(7, b"\x01" * 32)
    ds = RData_DS(key.key_tag, 7, 2, ds_digest(OWNER, bytes(key), 2))
    verdict = authenticate_dnskey_rrset(OWNER, [key], [], [ds], now=NOW)
    assert verdict.outcome is ChainOutcome.INSECURE
    assert "MUST be treated as insecure" in verdict.reason


def test_a_gost_digest_ds_introduces_nothing():
    """RFC 9906 §2¶1's mirror, on the other octet: Digest Type 3, algorithm innocent."""
    key = _dnskey(8, b"\x01" * 32)
    ds = RData_DS(key.key_tag, 8, 3, b"\x00" * 32)
    verdict = authenticate_dnskey_rrset(OWNER, [key], [], [ds], now=NOW)
    assert verdict.outcome is ChainOutcome.INSECURE


def test_a_deprecated_ds_in_a_mixed_set_is_simply_ignored():
    """§2¶1's second sentence: it takes *no* accepted DS to fall; one is enough to stand.

    With an acceptable SHA-256 DS beside the deprecated one, the child is
    introduced normally -- the deprecated record changes nothing -- and the
    verdict that follows is the ordinary §5.2¶5 story of a matched key and no
    self-signature, not the void-link INSECURE.
    """
    key = _dnskey(8, b"\x01" * 32)
    good = RData_DS(key.key_tag, 8, 2, ds_digest(OWNER, bytes(key), 2))
    bad = RData_DS(0, 5, 2, b"\x00" * 32)
    verdict = authenticate_dnskey_rrset(OWNER, [key], [], [bad, good], now=NOW)
    assert verdict.outcome is ChainOutcome.BOGUS
    assert "no RRSIG at all" in verdict.reason


def test_an_apex_signed_only_by_a_deprecated_algorithm_is_insecure_not_indeterminate():
    """§2¶2's route to the same fourth state, and the opt-in still tells states apart.

    A DNSKEY-form trust point matches the key directly (RFC 4033 §2's other anchor
    shape), so the deprecated self-signature is what decides: by default it is
    forbidden to believe, which §2¶2 names insecure -- nothing changes on a retry,
    so this is not Indeterminate. Open the gate and the junk key material is a
    *different* problem: the arithmetic could not run, which IS Indeterminate.
    Two states that used to collide in one word, told apart again.
    """
    _needs_backend()
    key = _dnskey(7, b"\x01" * 32)
    rrsig = _rrsig(
        7, key.key_tag, type_covered=int(DnsRType.DNSKEY), labels=2
    )  # the apex of example.net. is a two-label signer name
    default = authenticate_dnskey_rrset(OWNER, [key], [rrsig], [], now=NOW, trusted_dnskeys=[key])
    assert default.outcome is ChainOutcome.INSECURE
    assert "render unsupported" in default.reason
    opted = authenticate_dnskey_rrset(
        OWNER,
        [key],
        [rrsig],
        [],
        now=NOW,
        trusted_dnskeys=[key],
        allow_deprecated_sha1=True,
    )
    assert opted.outcome is ChainOutcome.INDETERMINATE


# ---------------------------------------------------------------------- the plumbing doors


def test_the_validator_holds_the_opt_in_for_a_whole_walk():
    assert Validator().allow_deprecated_sha1 is False
    assert Validator(allow_deprecated_sha1=True).allow_deprecated_sha1 is True


def test_the_resolver_holds_the_opt_in_too():
    """RecursiveResolver constructs offline, so the door itself is the cheap test."""
    from namespy.resolver import RecursiveResolver

    assert RecursiveResolver().allow_deprecated_sha1 is False
    assert RecursiveResolver(allow_deprecated_sha1=True).allow_deprecated_sha1 is True
