"""namespy.validate: a signed zone built whole, so it can be broken precisely.

The fixture is a three-level tree -- the root, ``test.``, ``zone.test.`` -- signed with
real RSA keys (RFC 5702, algorithm 8) over the real signing bytes, because the states
this module names only mean something if the signatures are the real thing: a
hand-written RRSIG can prove the plumbing but not that the plumbing computes. The root
key is configured as the trust anchor. ``sub.zone.test.`` is the deliberately unsigned
child -- its parent's NSEC names it with an NS-only bitmap and no DS bit -- and
``missing.zone.test.`` is the name nobody has ever registered.

Tamper tests rebuild the tree rather than mutating a shared one: a signature failure
should be attributable to the one octet this test moved, not to test-order dust.
"""

import base64
import datetime
from functools import cache

import pytest

from namespy import crypto
from namespy.anchors import TrustAnchor
from namespy.crypto import crypto_available
from namespy.dnssec import (
    ds_digest,
    nsec3_hash,
    pack_rsa_public_key,
    rrsig_label_count,
    rrsig_signed_data,
)
from namespy.enums import DnsResponseCode, DnsRType
from namespy.names import DomainName
from namespy.rdata import (
    RData_A,
    RData_DNSKEY,
    RData_DS,
    RData_NSEC,
    RData_NSEC3,
    RData_RRSIG,
)
from namespy.validate import DnssecStore, SecurityStatus, Validator

TTL = 3600
INC = 1_700_000_000
EXP = 2_000_000_000
NOW = 1_800_000_000

#: A signature window every RRSIG in the tree shares, straddling NOW.


def _needs_backend() -> None:
    if not crypto_available():
        pytest.skip("namespy[crypto] is not installed")


class R:
    """The minimal record shape a :class:`DnssecStore` consumes."""

    def __init__(self, name, rtype, rdata, ttl=TTL):
        self.name = DomainName(name)
        self.rtype = int(rtype)
        self.rclass = 1
        self.ttl = ttl
        self.rdata = rdata


def _make_key():
    from cryptography.hazmat.primitives.asymmetric import rsa

    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _dnskey(private, flags: int = 257):
    from cryptography.hazmat.primitives.asymmetric import rsa

    public: rsa.RSAPublicNumbers = private.public_key().public_numbers()
    return RData_DNSKEY(flags, 3, 8, pack_rsa_public_key(public.e, public.n))


def _sign(
    private,
    signer: str,
    owner: str,
    rtype: int,
    rdatas,
    *,
    labels: int | None = None,
    algorithm: int = 8,
):
    """A real PKCS#1 v1.5 signature over these rdatas, wrapped in the RRSIG that carries it."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    fields = {
        "type_covered": int(rtype),
        "algorithm": algorithm,
        "labels": rrsig_label_count(owner) if labels is None else labels,
        "original_ttl": TTL,
        "expiration": EXP,
        "inception": INC,
        "key_tag": _dnskey(private).key_tag,
        "signer_name": DomainName(signer),
    }
    placeholder = RData_RRSIG(signature=b"\x00" * 256, **fields)
    message = rrsig_signed_data(placeholder, owner, rdatas)
    signature = private.sign(message, padding.PKCS1v15(), hashes.SHA256())
    return RData_RRSIG(signature=signature, **fields)


@cache
def _pk(which: str):
    """The tree's signing keys, made on first use, never at import.

    CI runs the suite without ``namespy[crypto]`` installed -- that is the whole point
    of the skip guards -- and a module-level ``generate_private_key`` would crash
    collection on the missing import before any guard could say "skip".
    """
    return _make_key()


@cache
def _pub(which: str) -> RData_DNSKEY:
    return _dnskey(_pk(which))


def _anchor() -> TrustAnchor:
    return TrustAnchor(
        zone=".",
        key_tag=_pub("root").key_tag,
        algorithm=8,
        digest_type=2,
        digest=ds_digest(".", bytes(_pub("root")), 2),
        key_id="Kfixture.root",
        valid_from=datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC),
    )


def _nsec(next_domain, types):
    return RData_NSEC(next_domain, types)


def build_store(
    *,
    with_wildcard: bool = False,
    flip=None,
    drop=None,
    contradict: bool = False,
    nsec3: bool = False,
    bad_salt: bool = False,
    contradict_sub: bool = False,
    opt_out=(),
    www_sig_alg: int = 8,
    a_sig_alg: int = 8,
    ds_alg: int = 8,
):
    """The fixture tree as a store -- the whole vocabulary of the refusal tests.

    ``flip`` corrupts one RRset's signature; ``drop`` (name or set of names) leaves
    RRsets out; ``contradict`` gives ``www`` a bitmap listing the type its No Data
    answer denies; ``nsec3`` swaps the zone's NSEC chain for a real NSEC3 chain (the
    hashed owners, digests in canonical order); ``bad_salt`` makes that chain claim a
    salt its owner labels were not hashed with, so nothing matches; ``contradict_sub``
    lists the DS bit on the unsigned child's NSEC3; ``opt_out`` (owner names)
    sets the Opt-Out flag on the named NSEC3 records' RDATA before they are
    signed, which keeps a next-closer proof valid and forbids the AD bit
    (RFC 5155 §7.2.8, §9.2¶1); the ``*_alg``
    knobs sign one RRset with an algorithm no backend can attempt.
    """

    drops = {drop} if isinstance(drop, str) else set(drop or ())

    def wanted(name: str) -> bool:
        return name not in drops

    store = DnssecStore()

    def serve(zone: str, owner: str, rtype: int, rdatas, private, *, labels=None, algorithm=8):
        if not wanted(f"{owner}/{rtype}"):
            return
        rrsig = _sign(private, zone, owner, rtype, rdatas, labels=labels, algorithm=algorithm)
        if flip == f"{owner}/{rtype}":
            signature = bytearray(rrsig.signature)
            signature[-1] ^= 0x01
            rrsig = RData_RRSIG(
                rrsig.type_covered,
                rrsig.algorithm,
                rrsig.labels,
                rrsig.original_ttl,
                rrsig.expiration,
                rrsig.inception,
                rrsig.key_tag,
                rrsig.signer_name,
                bytes(signature),
            )
        records = [R(owner, rtype, data) for data in rdatas]
        records.append(R(owner, int(DnsRType.RRSIG), rrsig))
        store.add(records, zone=zone)

    # the root: its own keys, and the DS introducing test.
    serve(".", ".", int(DnsRType.DNSKEY), [_pub("root")], _pk("root"))
    serve(
        ".",
        "test.",
        int(DnsRType.DS),
        [RData_DS.for_dnskey("test.", _pub("test"))],
        _pk("root"),
        algorithm=ds_alg,
    )
    # test.: its keys, and the DS introducing zone.test.
    serve("test.", "test.", int(DnsRType.DNSKEY), [_pub("test")], _pk("test"))
    serve(
        "test.",
        "zone.test.",
        int(DnsRType.DS),
        [RData_DS.for_dnskey("zone.test.", _pub("zone"))],
        _pk("test"),
        algorithm=ds_alg,
    )
    # zone.test.: keys and data.
    serve("zone.test.", "zone.test.", int(DnsRType.DNSKEY), [_pub("zone")], _pk("zone"))
    wildcard_a = RData_A(b"\xc0\x00\x02\x02")
    if with_wildcard:
        serve("zone.test.", "*.zone.test.", int(DnsRType.A), [wildcard_a], _pk("zone"))
        # the expanded answer: the wildcard's bits under the queried name, signed as
        # the wildcard's bytes -- the RRSIG's Labels remembers which name was signed.
        store.add(
            [
                R("any.zone.test.", int(DnsRType.A), wildcard_a),
                R(
                    "any.zone.test.",
                    int(DnsRType.RRSIG),
                    _sign(_pk("zone"), "zone.test.", "*.zone.test.", int(DnsRType.A), [wildcard_a]),
                ),
            ],
            zone="zone.test.",
        )
    if nsec3:
        owners = {
            "zone.test.": [
                int(DnsRType.SOA),
                int(DnsRType.NS),
                int(DnsRType.DNSKEY),
                int(DnsRType.NSEC3),
            ],
            "sub.zone.test.": [int(DnsRType.NS)] + ([int(DnsRType.DS)] if contradict_sub else []),
            "www.zone.test.": [int(DnsRType.A)],
            "y.zone.test.": [int(DnsRType.TXT)],
        }
        if with_wildcard:
            owners["*.zone.test."] = [int(DnsRType.A)]
        digests = {o: nsec3_hash(o, iterations=0, salt=b"") for o in owners}
        order = sorted(owners, key=lambda o: digests[o])
        salt = b"ee" if bad_salt else b""
        for index, owner in enumerate(order):
            nxt = order[(index + 1) % len(order)]
            label = base64.b32hexencode(digests[owner]).decode("ascii").rstrip("=")
            serve(
                "zone.test.",
                f"{label}.zone.test.",
                int(DnsRType.NSEC3),
                [
                    RData_NSEC3(
                        1, 1 if owner in opt_out else 0, 0, salt, digests[nxt], owners[owner]
                    )
                ],
                _pk("zone"),
            )
    else:
        apex_types = [
            int(DnsRType.SOA),
            int(DnsRType.NS),
            int(DnsRType.DNSKEY),
            int(DnsRType.NSEC),
        ]
        if with_wildcard:
            # canonical order: *.zone.test. < sub < www < y < zone.test.
            serve(
                "zone.test.",
                "*.zone.test.",
                int(DnsRType.NSEC),
                [_nsec("sub.zone.test.", [int(DnsRType.A)])],
                _pk("zone"),
            )
            serve(
                "zone.test.",
                "zone.test.",
                int(DnsRType.NSEC),
                [_nsec("*.zone.test.", apex_types)],
                _pk("zone"),
            )
        else:
            serve(
                "zone.test.",
                "zone.test.",
                int(DnsRType.NSEC),
                [_nsec("sub.zone.test.", apex_types)],
                _pk("zone"),
            )
        serve(
            "zone.test.",
            "sub.zone.test.",
            int(DnsRType.NSEC),
            [_nsec("www.zone.test.", [int(DnsRType.NS)])],
            _pk("zone"),
        )
        www_types = [int(DnsRType.A)]
        if contradict:
            www_types.append(int(DnsRType.AAAA))
        serve(
            "zone.test.",
            "www.zone.test.",
            int(DnsRType.NSEC),
            [_nsec("y.zone.test.", www_types)],
            _pk("zone"),
            algorithm=www_sig_alg,
        )
        serve(
            "zone.test.",
            "y.zone.test.",
            int(DnsRType.NSEC),
            [_nsec("zone.test.", [int(DnsRType.TXT)])],
            _pk("zone"),
        )
    serve(
        "zone.test.",
        "www.zone.test.",
        int(DnsRType.A),
        [RData_A(b"\xc0\x00\x02\x01")],
        _pk("zone"),
        algorithm=a_sig_alg,
    )
    return store


def build_validator(**kwargs) -> Validator:
    no_anchor = kwargs.pop("no_anchor", False)
    anchors = [] if no_anchor else [_anchor()]
    return Validator(anchors=anchors, store=build_store(**kwargs), now=NOW)


# ------------------------------------------------------------------------------ the chain walk


def test_the_deep_zone_chains_from_the_root_anchor():
    _needs_backend()
    validator = build_validator()
    apex = validator.authenticate_zone("zone.test.")
    assert apex.status is SecurityStatus.SECURE
    assert apex.matched_key_tag == _pub("zone").key_tag
    assert len(apex.keys) == 1
    assert validator.authenticate_zone("test.").status is SecurityStatus.SECURE


def test_the_apex_with_no_anchor_configured_is_indeterminate():
    """Not bogus -- nothing contradicted; the validator simply has no trust point.

    This is RFC 4035 §4.3¶5 distilled: an unanchored signed root looks exactly like a
    hostile one to software that refuses to say "I cannot tell", and saying it wrong
    here means every zone below reports a forgery that has not happened.
    """
    _needs_backend()
    verdict = build_validator(no_anchor=True).authenticate_zone("zone.test.")
    assert verdict.status is SecurityStatus.INDETERMINATE
    assert "no trust anchor configured" in verdict.reason


def test_a_broken_root_key_severs_everything_below_it():
    _needs_backend()
    validator = build_validator(flip=f"./{int(DnsRType.DNSKEY)}")
    root = validator.authenticate_zone(".")
    assert root.status is SecurityStatus.BOGUS
    deep = validator.authenticate_zone("zone.test.")
    assert deep.status is SecurityStatus.BOGUS
    assert "stops at the parent" in deep.reason


def test_a_tampered_ds_boguses_the_child_it_introduces():
    _needs_backend()
    validator = build_validator(flip=f"test./{int(DnsRType.DS)}")
    test_zone = validator.authenticate_zone("test.")
    assert test_zone.status is SecurityStatus.BOGUS
    assert "DS RRset at the parent" in test_zone.reason


def test_a_zone_with_no_ds_and_no_proof_is_indeterminate_not_insecure():
    """The unsigned-and-the-unproven distinction, which is RFC 8020 §2¶3's whole basis.

    ``nowhere.test.`` really has no DS in this fixture -- but the parent supplied no
    signed proof of that, and an unprovable absence is §4.3¶5: the resolver has to go
    ask (§5.2¶6), not mark the subtree insecure and start answering from assumption.
    """
    _needs_backend()
    verdict = build_validator().authenticate_zone("nowhere.test.")
    assert verdict.status is SecurityStatus.INDETERMINATE
    assert "neither a DS" in verdict.reason


def test_a_ds_without_the_childs_keys_says_what_is_still_needed():
    _needs_backend()
    validator = build_validator(drop=f"zone.test./{int(DnsRType.DNSKEY)}")
    verdict = validator.authenticate_zone("zone.test.")
    assert verdict.status is SecurityStatus.INDETERMINATE
    assert "must be asked for" in verdict.reason


def test_the_unsigned_delegation_is_insecure_and_pulls_its_subtree_down():
    _needs_backend()
    validator = build_validator()
    sub = validator.authenticate_zone("sub.zone.test.")
    assert sub.status is SecurityStatus.INSECURE
    assert "5.2\u00b67" in sub.reason
    deeper = validator.authenticate_zone("deep.sub.zone.test.")
    assert deeper.status is SecurityStatus.INSECURE
    assert "stops at the parent" in deeper.reason


def test_a_directly_anchored_island_survives_a_broken_parent():
    """RFC 4035 §5.1: the parent's verdict is one path, not a veto.

    test. is anchored here *and* its DS at the root is tampered with -- the exact state
    of a zone whose registrar lost the DS update. A validator that let the parent's
    bogus leak downward would report the whole island forged despite holding the key
    itself; §5.2¶7's "MAY be used to re-establish an authentication path" is the door
    this test walks through.
    """
    _needs_backend()
    ds = RData_DS.for_dnskey("test.", _pub("test"))
    test_anchor = TrustAnchor(
        zone="test.",
        key_tag=ds.key_tag,
        algorithm=ds.algorithm,
        digest_type=ds.digest_type,
        digest=ds.digest,
        valid_from=datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC),
    )
    validator = Validator(
        anchors=[_anchor(), test_anchor],
        store=build_store(flip=f"test./{int(DnsRType.DS)}"),
        now=NOW,
    )
    assert validator.authenticate_zone("test.").status is SecurityStatus.SECURE
    assert validator.authenticate_zone("zone.test.").status is SecurityStatus.SECURE


def test_a_key_shaped_anchor_needs_no_digest_at_all():
    """RFC 4033 §2 allows the anchor to *be* the DNSKEY -- the RFC 9718 PublicKey element.

    The digest type below is one this package cannot compute, so the DS path is unusable
    by construction: only byte-identity with the configured key can authenticate this
    root, and it does.
    """
    _needs_backend()
    key_anchor = TrustAnchor(
        zone=".",
        key_tag=_pub("root").key_tag,
        algorithm=8,
        digest_type=99,
        digest=b"\x00" * 20,
        public_key=_pub("root").public_key,
        flags=257,
    )
    validator = Validator(anchors=[key_anchor], store=build_store(), now=NOW)
    verdict = validator.authenticate_zone(".")
    assert verdict.status is SecurityStatus.SECURE
    assert verdict.matched_key_tag == _pub("root").key_tag


def test_without_a_backend_the_tree_is_indeterminate_top_to_bottom(monkeypatch):
    _needs_backend()  # the tree it monkeypatches away from still has to be signed
    monkeypatch.setattr(crypto, "_BACKEND", None)
    monkeypatch.setattr(crypto, "_PROBED", True)
    validator = build_validator()
    for zone in (".", "test.", "zone.test."):
        verdict = validator.authenticate_zone(zone)
        assert verdict.status is SecurityStatus.INDETERMINATE, zone


def test_the_walk_is_memoised_per_zone():
    _needs_backend()
    validator = build_validator()
    assert validator.authenticate_zone("zone.test.") is validator.authenticate_zone("zone.test.")


def test_expired_signatures_are_bogus_not_indeterminate():
    """A window miss is a *check that ran and refused* -- expired data is contradicted data.

    RFC 4035 §5.3.1 puts the window among the MUST-conditions whose failure means the
    RRSIG MUST NOT be used; nothing about it is "could not tell", and a validator
    reporting Indeterminate over expired data invites the answer to be retried into
    permanence rather than fixed by the zone re-signing.
    """
    _needs_backend()
    validator = Validator(anchors=[_anchor()], store=build_store(), now=EXP + 10)
    assert validator.authenticate_zone(".").status is SecurityStatus.BOGUS


# ------------------------------------------------------------------------------ answers


def test_an_answer_validates_under_the_chain():
    _needs_backend()
    verdict = build_validator().validate_rrset("www.zone.test.", int(DnsRType.A))
    assert verdict.secure
    assert verdict.matched_key_tag == _pub("zone").key_tag
    assert str(verdict.zone) == "zone.test."


def test_an_extra_octet_in_the_answer_set_is_bogus():
    """Records are *added* to a store, never replaced -- so a set that outgrows its signature fails.

    This is the shape of the classic on-path answer edit: the genuine RR is still there
    (a splice, not a swap), so anything checking only "does a signed A for this name
    exist" waves it through. The RRset the signature covers is the whole bucket, and
    §5.3.2's reconstruction says so.
    """
    _needs_backend()
    validator = build_validator()
    validator.store.add(
        [R("www.zone.test.", int(DnsRType.A), RData_A(b"\xc1\x00\x02\x01"))],
        zone="zone.test.",
    )
    verdict = validator.validate_rrset("www.zone.test.", int(DnsRType.A))
    assert verdict.status is SecurityStatus.BOGUS


def test_unsigned_data_inside_a_secure_zone_is_bogus():
    """RFC 4033 §5 counts missing signatures as bogus material, in so many words."""
    _needs_backend()
    validator = build_validator()
    validator.store.add(
        [R("x.zone.test.", int(DnsRType.A), RData_A(b"\xc0\x00\x02\x09"))],
        zone="zone.test.",
    )
    verdict = validator.validate_rrset("x.zone.test.", int(DnsRType.A), zone="zone.test.")
    assert verdict.status is SecurityStatus.BOGUS
    assert "unsigned inside" in verdict.reason


def test_unsigned_data_below_a_provably_unsigned_zone_is_insecure():
    """The Insecure state doing its actual job: believing nothing, forbidding nothing.

    An unsigned answer below ``sub.zone.test.`` is *normal* -- that is what unsigned
    means down there -- and reporting it bogus would break every lookup into the
    unsigned half of the tree, which is what RFC 4035 §5.2¶10 tells a validator not to
    do. The cuts this state earns are the AD bit and the NXDOMAIN cut, not the answer.
    """
    _needs_backend()
    validator = build_validator()
    validator.store.add(
        [R("lamp.sub.zone.test.", int(DnsRType.A), RData_A(b"\xc0\x00\x02\x0a"))],
        zone="sub.zone.test.",
    )
    verdict = validator.validate_rrset(
        "lamp.sub.zone.test.", int(DnsRType.A), zone="sub.zone.test."
    )
    assert verdict.status is SecurityStatus.INSECURE


def test_unsigned_data_with_no_zone_stated_cannot_be_judged():
    _needs_backend()
    validator = build_validator()
    validator.store.add(
        [R("x.zone.test.", int(DnsRType.A), RData_A(b"\xc0\x00\x02\x09"))],
        zone="zone.test.",
    )
    verdict = validator.validate_rrset("x.zone.test.", int(DnsRType.A))
    assert verdict.status is SecurityStatus.INDETERMINATE
    assert "unsigned from not-yet-asked-about" in verdict.reason


def test_a_wildcard_answer_needs_and_gets_its_closer_match_denial():
    """RFC 4035 §5.3.4¶1: fewer Labels than the owner has is a claim, not a verdict.

    The fixture's wildcard A under ``any.zone.test.`` carries the wildcard's signature
    (Labels 2, signed at ``*.zone.test.``); it turns SECURE only because the zone's own
    NSEC chain proves nothing closer to ``any.zone.test.`` exists.
    """
    _needs_backend()
    validator = Validator(anchors=[_anchor()], store=build_store(with_wildcard=True), now=NOW)
    verdict = validator.validate_rrset("any.zone.test.", int(DnsRType.A))
    assert verdict.secure
    assert "wildcard-expanded" in verdict.reason


def test_a_wildcard_answer_without_a_denial_of_closer_names_is_indeterminate():
    _needs_backend()
    store = build_store(with_wildcard=True, drop=f"*.zone.test./{int(DnsRType.NSEC)}")
    validator = Validator(anchors=[_anchor()], store=store, now=NOW)
    verdict = validator.validate_rrset("any.zone.test.", int(DnsRType.A))
    assert verdict.status is SecurityStatus.INDETERMINATE
    assert "synthesised" in verdict.reason


# ------------------------------------------------------------------------------ denials


def test_a_proved_nxdomain_is_secure():
    _needs_backend()
    verdict = build_validator().validate_denial(
        "missing.zone.test.",
        int(DnsRType.A),
        rcode=DnsResponseCode.NAME_ERROR,
        zone="zone.test.",
    )
    assert verdict.secure
    assert verdict.matched_key_tag == _pub("zone").key_tag


def test_a_proved_no_data_answer_is_secure():
    _needs_backend()
    verdict = build_validator().validate_denial(
        "www.zone.test.",
        int(DnsRType.AAAA),
        rcode=DnsResponseCode.NO_ERROR,
        zone="zone.test.",
    )
    assert verdict.secure


def test_a_wildcard_no_data_answer_over_nsec3_is_secure():
    """The wire gap of increments E-H, closed: RFC 5155 §8.7 reached through §8.5.

    ``deep.zone.test.`` exists in no owner set -- the chain's asserting record covers
    it, correctly, because it does not exist -- and ``*.zone.test.`` exists holding A
    and nothing else. That pair is a wildcard No Data answer, §8.7's, and until the
    asserting span became the hinge into that section the validator convicted its own
    fixture: Bogus, and a SERVFAIL one layer up. Verdict must now read secure, with
    no compact bit involved and the AD flag still earned.
    """
    _needs_backend()
    validator = build_validator(nsec3=True, with_wildcard=True)
    verdict = validator.validate_denial(
        "deep.zone.test.",
        int(DnsRType.TXT),
        rcode=DnsResponseCode.NO_ERROR,
        zone="zone.test.",
    )
    assert verdict.status is SecurityStatus.SECURE, verdict.reason
    assert not verdict.via_compact
    assert verdict.ad_worthy


def test_a_forged_proof_signature_refuses_the_denial():
    """The geometry is perfect here -- and it still comes back BOGUS.

    One flipped octet in the signature over the NSEC that covers the denied name is
    all it takes: the shape validators never look at signatures, which is exactly why
    this layer exists between them and any policy that consumes their `True`.
    """
    _needs_backend()
    validator = build_validator(flip=f"www.zone.test./{int(DnsRType.NSEC)}")
    verdict = validator.validate_denial(
        "www.zone.test.",
        int(DnsRType.AAAA),
        rcode=DnsResponseCode.NO_ERROR,
        zone="zone.test.",
    )
    assert verdict.status is SecurityStatus.BOGUS
    assert "fails to verify" in verdict.reason


def test_a_bitmap_that_contradicts_its_own_denial_is_bogus_immediately():
    _needs_backend()
    validator = build_validator(contradict=True)
    verdict = validator.validate_denial(
        "www.zone.test.",
        int(DnsRType.AAAA),
        rcode=DnsResponseCode.NO_ERROR,
        zone="zone.test.",
    )
    assert verdict.status is SecurityStatus.BOGUS
    assert "bitmap" in verdict.reason


def test_a_secure_zone_that_sends_no_proof_cannot_have_denied_anything():
    _needs_backend()
    verdict = build_validator().validate_denial(
        "nope.test.",
        int(DnsRType.A),
        rcode=DnsResponseCode.NAME_ERROR,
        zone="test.",
    )
    assert verdict.status is SecurityStatus.INDETERMINATE
    assert "no NSEC/NSEC3 proof" in verdict.reason


def test_a_denial_from_a_provably_unsigned_zone_is_insecure():
    """RFC 8020 §2¶3, stated at last: an unsigned zone's NXDOMAIN proves nothing.

    sub.zone.test.'s keys reach no anchor -- its parent proved there is no DS -- so
    its denial lands Insecure whoever signed it. This is the verdict that decides
    whether a cached NXDOMAIN may cut a subtree, and it is the reason
    ``NxdomainPolicy.VALIDATED`` exists as a policy at all.
    """
    _needs_backend()
    verdict = build_validator().validate_denial(
        "anything.sub.zone.test.",
        int(DnsRType.A),
        rcode=DnsResponseCode.NAME_ERROR,
        zone="sub.zone.test.",
    )
    assert verdict.status is SecurityStatus.INSECURE
    assert "unauthenticated keys" in verdict.reason


def test_only_negative_rcodes_are_denials():
    _needs_backend()
    with pytest.raises(ValueError, match="NAME_ERROR or NO_ERROR"):
        build_validator().validate_denial(
            "www.zone.test.",
            int(DnsRType.A),
            rcode=DnsResponseCode.SERVER_FAILURE,
            zone="zone.test.",
        )


# ------------------------------------------------------------------------------ store mechanics


def test_parent_and_child_nsec_rrsets_at_one_name_never_merge():
    """The §5.3.2¶18 machinery, tested at the bucket level where it lives.

    The delegation case this store design exists for: parent and child each hold an
    NSEC at ``kid.example.`` with the same RTYPE, and neither may ever see the other's
    records in its RRset -- a merged bucket matches neither signature, which would
    make every signed delegation a self-inflicted bogus.
    """
    store = DnssecStore()
    parent_nsec = RData_NSEC("z.example.", [int(DnsRType.NS)])
    child_nsec = RData_NSEC("example.", [int(DnsRType.SOA), int(DnsRType.NS)])
    store.add([R("kid.example.", int(DnsRType.NSEC), parent_nsec)], zone="example.")
    store.add([R("kid.example.", int(DnsRType.NSEC), child_nsec)], zone="kid.example.")
    assert store.rdatas("kid.example.", int(DnsRType.NSEC), origin="example.") == (parent_nsec,)
    assert store.rdatas("kid.example.", int(DnsRType.NSEC), origin="kid.example.") == (child_nsec,)
    from namespy.nsec import proof_entries

    parents = proof_entries(store.proof_records("example."))
    kids = proof_entries(store.proof_records("kid.example."))
    assert [record for _owner, record in parents] == [parent_nsec]
    assert [record for _owner, record in kids] == [child_nsec]


def test_a_record_learned_twice_is_one_record():
    store = DnssecStore()
    a = RData_A(b"\xc0\x00\x02\x01")
    store.add([R("x.test.", int(DnsRType.A), a)], zone="test.")
    store.add([R("x.test.", int(DnsRType.A), a)], zone="test.")
    assert len(store.rdatas("x.test.", int(DnsRType.A))) == 1


def test_a_store_can_be_seeded_at_construction_and_refuses_opt():
    seed = [
        R("x.test.", int(DnsRType.A), RData_A(b"\xc0\x00\x02\x01")),
        R("x.test.", 41, b"not-an-rrset"),  # the OPT pseudo-RR: never data (RFC 6891 §6.2.1)
    ]
    store = DnssecStore(seed, zone="test.")
    assert store.has_rrset("x.test.", int(DnsRType.A))
    assert not store.has_rrset("x.test.", 41)
    assert {type(name).__name__ for name in store.names_with(int(DnsRType.A))} == {"DomainName"}
    verdict = Validator(store=store).validate_rrset("x.test.", int(DnsRType.A))
    assert "<ValidationVerdict indeterminate @x.test." in repr(verdict)


# ------------------------------------------------------------------------------ the NSEC3 leg


def _nsec3_validator(**kwargs) -> Validator:
    return Validator(anchors=[_anchor()], store=build_store(nsec3=True, **kwargs), now=NOW)


def test_the_nsec3_chain_walks_the_same_verdicts_as_nsec():
    _needs_backend()
    validator = _nsec3_validator()
    assert validator.authenticate_zone("zone.test.").status is SecurityStatus.SECURE
    sub = validator.authenticate_zone("sub.zone.test.")
    assert sub.status is SecurityStatus.INSECURE
    assert "5.2\u00b67" in sub.reason


def test_an_nsec3_nxdomain_denial_is_secure():
    _needs_backend()
    verdict = _nsec3_validator().validate_denial(
        "missing.zone.test.",
        int(DnsRType.A),
        rcode=DnsResponseCode.NAME_ERROR,
        zone="zone.test.",
    )
    assert verdict.secure


def test_an_nsec3_no_data_denial_is_secure():
    _needs_backend()
    verdict = _nsec3_validator().validate_denial(
        "www.zone.test.",
        int(DnsRType.AAAA),
        rcode=DnsResponseCode.NO_ERROR,
        zone="zone.test.",
    )
    assert verdict.secure


def test_an_nsec3_wildcard_answer_is_secure():
    _needs_backend()
    verdict = _nsec3_validator(with_wildcard=True).validate_rrset("any.zone.test.", int(DnsRType.A))
    assert verdict.secure
    assert "wildcard-expanded" in verdict.reason


def test_nsec3_records_hashed_with_another_salt_prove_nothing():
    """RFC 5155 §7.2.8 in one sentence: the owner label IS the hash -- with this salt.

    The chain here claims a salt its owner labels were never hashed with, so no digest
    matches and the unsigned child cannot be proved unsigned: Indeterminate, go ask
    again -- the one stance that cannot be talked into an answer by an off-spec zone.
    """
    _needs_backend()
    verdict = _nsec3_validator(bad_salt=True).authenticate_zone("sub.zone.test.")
    assert verdict.status is SecurityStatus.INDETERMINATE


def test_an_nsec3_listing_the_ds_bit_refuses_the_insecure_verdict():
    _needs_backend()
    verdict = _nsec3_validator(contradict_sub=True).authenticate_zone("sub.zone.test.")
    assert verdict.status is SecurityStatus.BOGUS


def test_an_insecure_verdict_needs_a_verified_proof_not_just_a_shaped_one():
    """The no-DS proof's own signature, forged: the child is Bogus, not Insecure.

    Flipping one octet in the NSEC that introduces the unsigned delegation is the
    attack RFC 4035 §5.2¶7 and RFC 5155 §8.6 jointly defend: strip a DS, sign the lie,
    and every name under the child "proves" itself unsigned -- answers downgrade to
    whatever the path carelessly answers. INSECURE is earned by a verifying proof or
    not at all.
    """
    _needs_backend()
    validator = build_validator(flip=f"sub.zone.test./{int(DnsRType.NSEC)}")
    verdict = validator.authenticate_zone("sub.zone.test.")
    assert verdict.status is SecurityStatus.BOGUS
    assert "no-DS proof" in verdict.reason


def test_a_proof_signed_with_an_unattemptable_algorithm_is_indeterminate():
    """Geometry fine, signature uncheckable -- which is §4.3¶5, not a verdict on the data."""
    _needs_backend()
    validator = build_validator(www_sig_alg=99)
    verdict = validator.validate_denial(
        "www.zone.test.",
        int(DnsRType.AAAA),
        rcode=DnsResponseCode.NO_ERROR,
        zone="zone.test.",
    )
    assert verdict.status is SecurityStatus.INDETERMINATE
    assert "could not be verified" in verdict.reason


def test_an_unsigned_proof_in_a_secure_zone_is_bogus():
    """An unsigned NSEC among the proofs is contradicted data, not missing data.

    The zone authenticated as secure, and a secure zone signs every RRset it serves
    (RFC 4035 §3.1.1); a proof with no signature is either a stripper on path or a
    server that lied about being signed, and RFC 4033 §5 files "missing signatures"
    under Bogus by name.
    """
    _needs_backend()
    validator = build_validator()
    validator.store.add(
        [R("q.zone.test.", int(DnsRType.NSEC), _nsec("y.zone.test.", [int(DnsRType.TXT)]))],
        zone="zone.test.",
    )
    verdict = validator.validate_denial(
        "www.zone.test.",
        int(DnsRType.AAAA),
        rcode=DnsResponseCode.NO_ERROR,
        zone="zone.test.",
    )
    assert verdict.status is SecurityStatus.BOGUS
    assert "carries no signature" in verdict.reason


def test_an_answer_signed_with_an_unattemptable_algorithm_is_indeterminate():
    _needs_backend()
    verdict = build_validator(a_sig_alg=99).validate_rrset("www.zone.test.", int(DnsRType.A))
    assert verdict.status is SecurityStatus.INDETERMINATE
    assert "could not be checked" in verdict.reason


def test_a_ds_signed_with_an_unattemptable_algorithm_leaves_the_child_unjudged():
    _needs_backend()
    verdict = build_validator(ds_alg=99).authenticate_zone("zone.test.")
    assert verdict.status is SecurityStatus.INDETERMINATE
    assert "DS RRset at the parent" in verdict.reason


def test_an_answer_under_a_broken_signer_reports_the_chain_not_the_arithmetic():
    _needs_backend()
    validator = build_validator(flip=f"./{int(DnsRType.DNSKEY)}")
    verdict = validator.validate_rrset("www.zone.test.", int(DnsRType.A))
    assert verdict.status is SecurityStatus.BOGUS
    assert "signer zone.test." in verdict.reason


def test_unsigned_data_in_a_bogus_zone_propagates_the_bogus():
    _needs_backend()
    validator = build_validator(flip=f"./{int(DnsRType.DNSKEY)}")
    validator.store.add(
        [R("x.zone.test.", int(DnsRType.A), RData_A(b"\xc0\x00\x02\x09"))],
        zone="zone.test.",
    )
    verdict = validator.validate_rrset("x.zone.test.", int(DnsRType.A), zone="zone.test.")
    assert verdict.status is SecurityStatus.BOGUS
    assert "walk stops at the parent" in verdict.reason


def test_a_wildcard_in_a_zone_that_sent_no_proofs_at_all_is_indeterminate():
    _needs_backend()
    store = build_store(
        with_wildcard=True,
        drop={
            f"*.zone.test./{int(DnsRType.NSEC)}",
            f"zone.test./{int(DnsRType.NSEC)}",
            f"sub.zone.test./{int(DnsRType.NSEC)}",
            f"www.zone.test./{int(DnsRType.NSEC)}",
            f"y.zone.test./{int(DnsRType.NSEC)}",
        },
    )
    validator = Validator(anchors=[_anchor()], store=store, now=NOW)
    verdict = validator.validate_rrset("any.zone.test.", int(DnsRType.A))
    assert verdict.status is SecurityStatus.INDETERMINATE
    assert "5.3.4\u00b61" in verdict.reason


def test_the_root_with_an_empty_store_says_what_is_missing():
    _needs_backend()
    verdict = Validator(anchors=[_anchor()], now=NOW).authenticate_zone(".")
    assert verdict.status is SecurityStatus.INDETERMINATE
    assert "no DNSKEY RRset for the root" in verdict.reason


# ------------------------------------------------------------------------------ the live root


def test_the_live_root_validates_as_an_answer_too():
    """The captured signed DNSKEY RRset, through the whole new layer at once.

    Chain walk, signer-derived zone, and the self-signature under the IANA-published
    anchor -- on the live octets ``test_dnssec_anchors`` pins and cross-checks. If
    this test goes BOGUS while its neighbours hold, the chain composition broke, not
    the arithmetic.
    """
    _needs_backend()
    import test_dnssec_anchors as live

    from namespy.packet import DnsPacket

    store = DnssecStore()
    packet, _used = DnsPacket.parse(bytes.fromhex(live.ROOT_DNSKEY_WIRE))
    store.add(packet.answers, zone=".")
    validator = Validator(anchors=live._ANCHORS, store=store, now=live.ROOT_NOW)
    verdict = validator.validate_rrset(".", int(DnsRType.DNSKEY))
    assert verdict.secure
    assert verdict.matched_key_tag == 38696
    assert str(verdict.zone) == "."


# ----------------------------------------------------------------------- the fetch hints
#
# RFC 4035 §5.2¶6 makes going after a missing DS the *resolver's* duty; the
# Validator's half of that contract is naming the one query that would close the
# gap, once, so the loop above it can spend queries without spinning.


def test_a_missing_key_set_names_the_query_that_would_supply_it():
    _needs_backend()
    validator = build_validator(drop="zone.test./48")
    verdict = validator.authenticate_zone("zone.test.")
    assert verdict.status is SecurityStatus.INDETERMINATE
    assert verdict.fetch_hint is not None
    name, rtype, from_zone = verdict.fetch_hint
    assert (str(name), int(rtype), str(from_zone)) == ("zone.test.", 48, "zone.test.")


def test_an_unanswered_hint_is_not_offered_twice():
    """After a failed fetch the second verdict says "nothing left to ask"."""
    _needs_backend()
    validator = build_validator(drop="zone.test./48")
    assert validator.authenticate_zone("zone.test.").fetch_hint is not None
    validator.invalidate()  # what the resolver does after a fetch returns nothing
    second = validator.authenticate_zone("zone.test.")
    assert second.status is SecurityStatus.INDETERMINATE
    assert second.fetch_hint is None


def test_a_fetched_key_set_completes_the_chain_after_invalidate():
    """The hint loop's success path: offer, invalidate, re-climb -- Secure."""
    _needs_backend()
    validator = build_validator(drop="zone.test./48")
    assert validator.authenticate_zone("zone.test.").fetch_hint is not None
    dnskey = _pub("zone")
    validator.store.add(
        [
            R("zone.test.", int(DnsRType.DNSKEY), dnskey),
            R(
                "zone.test.",
                int(DnsRType.RRSIG),
                _sign(_pk("zone"), "zone.test.", "zone.test.", int(DnsRType.DNSKEY), [dnskey]),
            ),
        ],
        zone="zone.test.",
    )
    validator.invalidate()
    assert validator.authenticate_zone("zone.test.").status is SecurityStatus.SECURE


def test_an_unproved_absent_ds_asks_for_the_ds_of_the_parent():
    """§5.2¶6's exact sentence, as data: query the parent for the DS."""
    _needs_backend()
    verdict = build_validator().authenticate_zone("nowhere.test.")
    assert verdict.status is SecurityStatus.INDETERMINATE
    assert verdict.fetch_hint is not None
    name, rtype, from_zone = verdict.fetch_hint
    assert (str(name), int(rtype), str(from_zone)) == ("nowhere.test.", 43, "test.")


def test_a_denial_inherits_the_hint_its_zone_could_not_resolve():
    """The fetch loop drives validate_denial, so the hint must survive propagation."""
    _needs_backend()
    verdict = build_validator(drop="zone.test./48").validate_denial(
        "missing.zone.test.",
        int(DnsRType.A),
        rcode=DnsResponseCode.NAME_ERROR,
        zone="zone.test.",
    )
    assert verdict.status is SecurityStatus.INDETERMINATE
    assert verdict.fetch_hint is not None
    assert str(verdict.fetch_hint[0]) == "zone.test."


def test_invalidate_reopens_conclusions_but_not_requests():
    """One method clears the memo; the asked-question ledger deliberately survives."""
    _needs_backend()
    validator = build_validator()
    assert validator.authenticate_zone("zone.test.").secure
    validator.invalidate()
    # The memo is gone but the data remains, so the conclusion re-derives the same.
    assert validator.authenticate_zone("zone.test.").secure
    # And a hint spent before the invalidate stays spent.
    other = build_validator(drop="zone.test./48")
    assert other.authenticate_zone("zone.test.").fetch_hint is not None
    other.invalidate()
    assert other.authenticate_zone("zone.test.").fetch_hint is None


# ------------------------------------------------------------- Opt-Out and the AD bit
#
# RFC 5155 §9.2¶1: an Opt-Out span may carry the next closer of a closest encloser
# proof -- denying the DS is exactly what Opt-Out proves -- yet the response
# "MUST NOT" then claim AD, because the covered name "may or may not exist as an
# insecure delegation": a part of the answer went cryptographically unchecked.


def _next_closer_owner(qname: str, *, wildcard: bool = False) -> str:
    """Which NSEC3 of the fixture's chain covers the hash of *qname* itself.

    Recomputes the fixture's own digest ordering rather than trusting a fixed
    name: the test must flag the exact record nsec.py will consult as the next
    closer's cover, and that is whichever span the name's hash falls into,
    spans running (owner, next] and the last wrapping to the first.
    """
    owners = ["zone.test.", "sub.zone.test.", "www.zone.test.", "y.zone.test."]
    if wildcard:
        owners.append("*.zone.test.")
    digests = {o: nsec3_hash(o, iterations=0, salt=b"") for o in owners}
    target = nsec3_hash(qname, iterations=0, salt=b"")
    order = sorted(owners, key=lambda o: digests[o])
    for index, owner in enumerate(order):
        nxt = order[(index + 1) % len(order)]
        low, high = digests[owner], digests[nxt]
        if high < low:  # the wrapping span: above the greatest or no greater than the least
            if target > low or target <= high:
                return owner
        elif low < target <= high:
            return owner
    raise AssertionError("no span covered the name -- the fixture moved")


def test_an_opt_out_next_closer_proves_the_denial_but_not_the_ad_bit():
    _needs_backend()
    covering = _next_closer_owner("missing.zone.test.")
    validator = _nsec3_validator(opt_out=(covering,))
    verdict = validator.validate_denial(
        "missing.zone.test.",
        int(DnsRType.A),
        rcode=DnsResponseCode.NAME_ERROR,
        zone="zone.test.",
    )
    assert verdict.secure  # §7.2.8: denying the next closer's DS is what Opt-Out proves
    assert verdict.via_opt_out
    assert not verdict.ad_worthy  # §9.2¶1's MUST NOT
    assert verdict.zone is not None
    assert str(verdict.zone) == "zone.test."


def test_a_signed_next_closer_earns_the_ad_bit_it_denied_opt_out():
    """The control: the same denial, nothing Opt-Out, AD worthy."""
    _needs_backend()
    covering = _next_closer_owner("missing.zone.test.")
    plain = _nsec3_validator()  # opt_out=() -- the covering record carries the flag clear
    assert str(covering)  # the fixture and this helper agree on where the name lives
    verdict = plain.validate_denial(
        "missing.zone.test.",
        int(DnsRType.A),
        rcode=DnsResponseCode.NAME_ERROR,
        zone="zone.test.",
    )
    assert verdict.secure
    assert verdict.via_opt_out is False
    assert verdict.ad_worthy
    # And the NSEC leg never has an Opt-Out to worry about.
    nsec_verdict = build_validator().validate_denial(
        "missing.zone.test.",
        int(DnsRType.A),
        rcode=DnsResponseCode.NAME_ERROR,
        zone="zone.test.",
    )
    assert nsec_verdict.ad_worthy


def test_a_wildcard_answer_behind_an_opt_out_span_earns_no_ad():
    """§9.2 is about closest-encloser proofs, and a wildcard answer carries one.

    The closer-match denial of RFC 4035 §5.3.4¶1 IS a closest-encloser proof;
    when Opt-Out covers its next closer, the answered name might instead have
    been (or hidden) an insecure delegation whose data nobody signed. The
    wildcard answer stands -- but the walk may not vouch for it.
    """
    _needs_backend()
    covering = _next_closer_owner("any.zone.test.", wildcard=True)
    validator = _nsec3_validator(with_wildcard=True, opt_out=(covering,))
    verdict = validator.validate_rrset("any.zone.test.", int(DnsRType.A))
    assert verdict.secure
    assert "wildcard-expanded" in verdict.reason
    assert verdict.via_opt_out
    assert not verdict.ad_worthy
    plain = _nsec3_validator(with_wildcard=True).validate_rrset("any.zone.test.", int(DnsRType.A))
    assert plain.secure
    assert plain.ad_worthy
