"""IDNA2008 label processing: the punycode codec and the A-label boundary.

The heart of this file is RFC 3492 section 7.1 -- the spec's own sample
strings, every code point transcribed from the listing, each paired with
the Punycode the spec prints for it.  If those pass in both directions,
sections 6.1-6.3 have been transcribed correctly; the rest of the file is
section 6.2/6.4's failure modes and the RFC 5891/5890 label rules around
the codec.
"""

import pytest

from namespy import __main__ as cli
from namespy.idna import (
    IdnaError,
    _adapt,
    label_to_ascii,
    label_to_unicode,
    punycode_decode,
    punycode_encode,
    to_ascii,
    to_unicode,
)
from namespy.names import DomainName


def _cp(*codes: int) -> str:
    """A string from code points, so every test vector is ASCII source."""
    return "".join(chr(c) for c in codes)


# (label text, Punycode body) from RFC 3492 section 7.1, examples A-R.
# Bodies are the encoder's canonical output: literal code points copy with
# their original case (section 6.3), encoded digits are lowercase (section
# 5 para 6, and RFC 5890 section 2.3.1 para 4).  The spec's printed (I)
# shows its digits as "Dot" -- 'D' and 'd' carry the same digit-value
# (section 5 para 4), so both spellings decode identically; lowercase is
# canonical.
VECTORS = [
    # (A) Arabic (Egyptian)
    (
        _cp(
            0x644,
            0x64A,
            0x647,
            0x645,
            0x627,
            0x628,
            0x62A,
            0x643,
            0x644,
            0x645,
            0x648,
            0x634,
            0x639,
            0x631,
            0x628,
            0x64A,
            0x61F,
        ),
        "egbpdaj6bu4bxfgehfvwxn",
    ),
    # (B) Chinese (simplified)
    (
        _cp(0x4ED6, 0x4EEC, 0x4E3A, 0x4EC0, 0x4E48, 0x4E0D, 0x8BF4, 0x4E2D, 0x6587),
        "ihqwcrb4cv8a8dqg056pqjye",
    ),
    # (C) Chinese (traditional)
    (
        _cp(0x4ED6, 0x5011, 0x7232, 0x4EC0, 0x9EBD, 0x4E0D, 0x8AAA, 0x4E2D, 0x6587),
        "ihqwctvzc91f659drss3x8bo0yb",
    ),
    # (D) Czech
    (
        _cp(
            0x50,
            0x72,
            0x6F,
            0x10D,
            0x70,
            0x72,
            0x6F,
            0x73,
            0x74,
            0x11B,
            0x6E,
            0x65,
            0x6D,
            0x6C,
            0x75,
            0x76,
            0xED,
            0x10D,
            0x65,
            0x73,
            0x6B,
            0x79,
        ),
        "Proprostnemluvesky-uyb24dma41a",
    ),
    # (E) Hebrew
    (
        _cp(
            0x5DC,
            0x5DE,
            0x5D4,
            0x5D4,
            0x5DD,
            0x5E4,
            0x5E9,
            0x5D5,
            0x5D8,
            0x5DC,
            0x5D0,
            0x5DE,
            0x5D3,
            0x5D1,
            0x5E8,
            0x5D9,
            0x5DD,
            0x5E2,
            0x5D1,
            0x5E8,
            0x5D9,
            0x5EA,
        ),
        "4dbcagdahymbxekheh6e0a7fei0b",
    ),
    # (F) Hindi (Devanagari)
    (
        _cp(
            0x92F,
            0x939,
            0x932,
            0x94B,
            0x917,
            0x939,
            0x93F,
            0x928,
            0x94D,
            0x926,
            0x940,
            0x915,
            0x94D,
            0x92F,
            0x94B,
            0x902,
            0x928,
            0x939,
            0x940,
            0x902,
            0x92C,
            0x94B,
            0x932,
            0x938,
            0x915,
            0x924,
            0x947,
            0x939,
            0x948,
            0x902,
        ),
        "i1baa7eci9glrd9b2ae1bj0hfcgg6iyaf8o0a1dig0cd",
    ),
    # (G) Japanese (kanji and hiragana)
    (
        _cp(
            0x306A,
            0x305C,
            0x307F,
            0x3093,
            0x306A,
            0x65E5,
            0x672C,
            0x8A9E,
            0x3092,
            0x8A71,
            0x3057,
            0x3066,
            0x304F,
            0x308C,
            0x306A,
            0x3044,
            0x306E,
            0x304B,
        ),
        "n8jok5ay5dzabd5bym9f0cm5685rrjetr6pdxa",
    ),
    # (H) Korean (Hangul syllables)
    (
        _cp(
            0xC138,
            0xACC4,
            0xC758,
            0xBAA8,
            0xB4E0,
            0xC0AC,
            0xB78C,
            0xB4E4,
            0xC774,
            0xD55C,
            0xAD6D,
            0xC5B4,
            0xB97C,
            0xC774,
            0xD574,
            0xD55C,
            0xB2E4,
            0xBA74,
            0xC5BC,
            0xB9C8,
            0xB098,
            0xC88B,
            0xC744,
            0xAE4C,
        ),
        "989aomsvi5e83db1d2a355cv1e0vak1dwrv93d5xbh15a0dt30a5jpsd879ccm6fea98c",
    ),
    # (I) Russian (Cyrillic)
    (
        _cp(
            0x43F,
            0x43E,
            0x447,
            0x435,
            0x43C,
            0x443,
            0x436,
            0x435,
            0x43E,
            0x43D,
            0x438,
            0x43D,
            0x435,
            0x433,
            0x43E,
            0x432,
            0x43E,
            0x440,
            0x44F,
            0x442,
            0x43F,
            0x43E,
            0x440,
            0x443,
            0x441,
            0x441,
            0x43A,
            0x438,
        ),
        "b1abfaaepdrnnbgefbadotcwatmq2g4l",
    ),
    # (J) Spanish
    (
        _cp(
            0x50,
            0x6F,
            0x72,
            0x71,
            0x75,
            0xE9,
            0x6E,
            0x6F,
            0x70,
            0x75,
            0x65,
            0x64,
            0x65,
            0x6E,
            0x73,
            0x69,
            0x6D,
            0x70,
            0x6C,
            0x65,
            0x6D,
            0x65,
            0x6E,
            0x74,
            0x65,
            0x68,
            0x61,
            0x62,
            0x6C,
            0x61,
            0x72,
            0x65,
            0x6E,
            0x45,
            0x73,
            0x70,
            0x61,
            0xF1,
            0x6F,
            0x6C,
        ),
        "PorqunopuedensimplementehablarenEspaol-fmd56a",
    ),
    # (K) Vietnamese
    (
        _cp(
            0x54,
            0x1EA1,
            0x69,
            0x73,
            0x61,
            0x6F,
            0x68,
            0x1ECD,
            0x6B,
            0x68,
            0xF4,
            0x6E,
            0x67,
            0x74,
            0x68,
            0x1EC3,
            0x63,
            0x68,
            0x1EC9,
            0x6E,
            0xF3,
            0x69,
            0x74,
            0x69,
            0x1EBF,
            0x6E,
            0x67,
            0x56,
            0x69,
            0x1EC7,
            0x74,
        ),
        "TisaohkhngthchnitingVit-kjcr8268qyxafd2f1b9g",
    ),
    # (L) 3<nen>B<gumi><kinpachi><sensei>
    (_cp(0x33, 0x5E74, 0x42, 0x7D44, 0x91D1, 0x516B, 0x5148, 0x751F), "3B-ww4c5e180e575a65lsy2b"),
    # (M) <amuro><namie>-with-SUPER-MONKEYS
    (
        _cp(
            0x5B89,
            0x5BA4,
            0x5948,
            0x7F8E,
            0x6075,
            0x2D,
            0x77,
            0x69,
            0x74,
            0x68,
            0x2D,
            0x53,
            0x55,
            0x50,
            0x45,
            0x52,
            0x2D,
            0x4D,
            0x4F,
            0x4E,
            0x4B,
            0x45,
            0x59,
            0x53,
        ),
        "-with-SUPER-MONKEYS-pc58ag80a8qai00g7n9n",
    ),
    # (N) Hello-Another-Way-<sorezore><no><basho>
    (
        _cp(
            0x48,
            0x65,
            0x6C,
            0x6C,
            0x6F,
            0x2D,
            0x41,
            0x6E,
            0x6F,
            0x74,
            0x68,
            0x65,
            0x72,
            0x2D,
            0x57,
            0x61,
            0x79,
            0x2D,
            0x305D,
            0x308C,
            0x305E,
            0x308C,
            0x306E,
            0x5834,
            0x6240,
        ),
        "Hello-Another-Way--fc4qua05auwb3674vfr0b",
    ),
    # (O) <hitotsu><yane><no><shita>2
    (_cp(0x3072, 0x3068, 0x3064, 0x5C4B, 0x6839, 0x306E, 0x4E0B, 0x32), "2-u9tlzr9756bt3uc0v"),
    # (P) Maji<de>Koi<suru>5<byou><mae>
    (
        _cp(0x4D, 0x61, 0x6A, 0x69, 0x3067, 0x4B, 0x6F, 0x69, 0x3059, 0x308B, 0x35, 0x79D2, 0x524D),
        "MajiKoi5-783gue6qz075azm5e",
    ),
    # (Q) <pafii>de<runba>
    (_cp(0x30D1, 0x30D5, 0x30A3, 0x30FC, 0x64, 0x65, 0x30EB, 0x30F3, 0x30D0), "de-jg4avhby1noc0d"),
    # (R) <sono><supiido><de>
    (_cp(0x305D, 0x306E, 0x30B9, 0x30D4, 0x30FC, 0x30C9, 0x3067), "d9juau41awczczp"),
]


@pytest.mark.parametrize(("text", "body"), VECTORS, ids=range(len(VECTORS)))
def test_rfc_3492_section_7_1_encode(text: str, body: str) -> None:
    assert punycode_encode(text) == body


@pytest.mark.parametrize(("text", "body"), VECTORS, ids=range(len(VECTORS)))
def test_rfc_3492_section_7_1_decode(text: str, body: str) -> None:
    assert punycode_decode(body) == text


def test_example_s_pure_basic_string_gets_the_delimiter() -> None:
    # Section 7.1's last example "breaks the existing rules for host name
    # labels ... IDNA never encodes pure ASCII labels" -- it is a codec
    # test, not an IDNA one: section 6.3 appends the delimiter when b > 0.
    assert punycode_encode("-> $1.00 <-") == "-> $1.00 <--"
    assert punycode_decode("-> $1.00 <--") == "-> $1.00 <-"


def test_decoder_reads_uppercase_digits_too() -> None:
    # Section 5 para 6: "a decoder MUST recognize the letters in both
    # uppercase and lowercase forms (including mixtures of both forms)".
    b = _cp(0x4ED6, 0x4EEC, 0x4E3A, 0x4EC0, 0x4E48, 0x4E0D, 0x8BF4, 0x4E2D, 0x6587)
    assert punycode_decode("IHQWCRB4CV8A8DQG056PQJYE") == b
    assert punycode_decode("ihqwcrb4CV8a8dQg056pqjye") == b


def test_adaptation_matches_the_section_7_2_trace() -> None:
    # The decoding trace of example B prints the bias after each delta:
    # 21, 20, 13, 17, 32, 23, 25, 84, 90.  Four checkpoints -- the first
    # (dampened), a middle one, and the last two (through the divisor loop
    # twice) -- say section 6.1 was transcribed.
    assert _adapt(19853, 1, True) == 21
    assert _adapt(599, 5, False) == 32
    assert _adapt(46301, 8, False) == 84
    assert _adapt(88531, 9, False) == 90


def test_decoding_trace_l_insertion_order() -> None:
    # Section 7.2's second trace ends at 0033 5E74 0042 7D44 91D1 516B
    # 5148 751F: the literal "3B" and six deltas whose insertions land at
    # positions 0..7 of the growing string, not in input order.
    assert punycode_decode("3B-ww4c5e180e575a65lsy2b") == _cp(
        0x33, 0x5E74, 0x42, 0x7D44, 0x91D1, 0x516B, 0x5148, 0x751F
    )


def test_the_decoder_is_a_bijection_on_one_valid_string() -> None:
    # Section 6.2 para 4: "there is only one encoded string that can
    # represent a given sequence of integers". z=25 breaks each delta
    # below t=26, so ten z's are several small deltas -- a string that
    # decodes cleanly and must re-encode identically.
    decoded = punycode_decode("z" * 10)
    assert punycode_encode(decoded) == "z" * 10


# --- section 6.2/6.4 failure modes -------------------------------------


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("9", "unexpected end of input"),  # a digit run that never terminates
        ("9-z", "unexpected end of input"),  # ditto, past a literal part
        ("!", "no digit-value"),
        ("-a", "no digit-value"),  # section 6.2: with zero literals consumed
        # the delimiter is not "consumed one more", so it fails as a digit
        ("z" * 6 + "!", "no digit-value"),
    ],
)
def test_decoder_fails_malformed_input(body: str, message: str) -> None:
    with pytest.raises(IdnaError, match=message):
        punycode_decode(body)


def test_decoder_rejects_a_non_ascii_string() -> None:
    # Section 6.2 copies literals "fail on any non-basic code point", and
    # its digits are ASCII; an encoded string is ASCII by construction
    # (RFC 5891 section 4.2.1 para 2: "the requirement that all characters
    # be ASCII").
    with pytest.raises(IdnaError, match="non-ASCII"):
        punycode_decode("ih\u00f1qwcrb4cv8a8dqg056pqjye")


def test_decoder_fails_on_overflow() -> None:
    # Section 6.4: "overflow handling is necessary because the inputs are
    # not necessarily valid IDNA labels". 9 is digit-value 35, t never
    # exceeds 26, so eight 9's never break their delta run and w keeps
    # multiplying -- the index check of A + B*C (section 6.4 para 2, with
    # maxint per section 6.4 para 1 and erratum 265) fires before any
    # runaway arithmetic can.

    with pytest.raises(IdnaError, match="overflow"):
        punycode_decode("9" * 8)


def test_encoder_refuses_code_points_outside_the_domain() -> None:
    # Section 5: code points are 0..10FFFF "but not D800..DFFF".
    with pytest.raises(IdnaError, match="surrogates"):
        punycode_encode("a\ud800b")


def test_decoder_accepts_lone_non_basic_inserts() -> None:
    # "a" is one delta encoding U+0080; section 6.2's braced "fail if n is
    # basic" is elided for Punycode (section 6.2 para 2) precisely because
    # n can never land below 128. Codec-level acceptance is fine -- the
    # IDNA layer is what decides U+0080 is not a label character.
    assert punycode_decode("a") == "\u0080"


# --- the IDNA layer: RFC 5891 sections 4.4, 5.3, 5.4 -------------------


def test_known_answers_from_the_registry_world() -> None:
    # Not from the RFCs, but from the zones themselves: these are how the
    # sentences actually register.
    assert to_ascii("m\u00fcnchen.de") == "xn--mnchen-3ya.de"
    assert to_ascii("b\u00fccher.example") == "xn--bcher-kva.example"


def test_conversion_is_idempotent() -> None:
    once = to_ascii("m\u00fcnchen.example")
    assert to_ascii(once) == once


def test_pure_ascii_labels_pass_through_untouched() -> None:
    # RFC 3492 section 7.1, note before example S: "IDNA never encodes
    # pure ASCII labels". Case is the wire layer's business (RFC 2181
    # section 11), not this function's.
    assert to_ascii("EXAMPLE.com") == "EXAMPLE.com"
    assert label_to_ascii("127") == "127"  # a reverse-mapping label, too


def test_root_and_empty_names_survive() -> None:
    assert to_ascii("") == ""
    assert to_ascii(".") == "."  # the root, spelled with its one empty label


def test_uppercase_u_label_needs_the_opt_in_fold() -> None:
    # IDNA2008 maps nothing (RFC 5891 appendix A; the RFC 5892 tables put
    # A-Z in DISALLOWED). The fold that from_unicode and the CLI apply is
    # the DNS's own ASCII-only equivalence (RFC 5890 section 2.3.2.4).
    with pytest.raises(IdnaError, match="ASCII uppercase"):
        label_to_ascii("M\u00fcnchen")
    assert label_to_ascii("M\u00fcnchen", map_ascii_case=True) == "xn--mnchen-3ya"
    # And the fold is ASCII-only: U+00DC is not U+005A's neighbour, so a
    # non-ASCII uppercase letter survives exactly as the strict reading
    # demands -- m\u00dcnchen is a different label from m\u00fcnchen.
    assert to_ascii("M\u00dcNCHEN.de", map_ascii_case=True) == "xn--mnchen-psa.de"


@pytest.mark.parametrize(
    ("label", "message"),
    [
        ("\u0378", "unassigned"),  # a gap in the Greek block, stable across
        # versions -- section 5.4's UNASSIGNED test, against the Unicode
        # this application actually uses (section 5.4 para 9)
        ("bu\u0308cher", "NFC"),  # decomposed: section 4.1 demands NFC
        ("\u0301x", "combining mark"),  # section 4.2.3.2
        ("-m\u00fcnchen", "hyphen restriction"),  # section 4.2.3.1
        ("m\u00fcnchen-", "hyphen restriction"),
        ("m\u00fc--nchen", "hyphen restriction"),  # "--" at positions 3..4
        ("m\u00fcn\u00a0chen", "control, separator"),  # NBSP: Zs
        ("m\u00fcn chen", "control, separator"),  # space inside a U-label
        ("m\u00fcn\u0001chen", "control, separator"),  # Cc
        ("m\u00fc\ue000chen", "private-use"),  # Co
    ],
)
def test_u_label_rejections(label: str, message: str) -> None:
    with pytest.raises(IdnaError, match=message):
        label_to_ascii(label)


def test_encoded_labels_obey_the_length_limit() -> None:
    # RFC 5891 section 4.4 para 1: the A-label "must, of course, conform to
    # the length limits imposed by the DNS" -- 63, of which the prefix
    # takes 4 (RFC 5890 section 2.3.1 para 3).
    with pytest.raises(IdnaError, match="over 63"):
        label_to_ascii("a" * 60 + "\u00fc")
    # And a U-label whose encoding fits is fine: 31 hiragana compress to
    # well under the limit.
    assert len(label_to_ascii("\u3042" * 31)) <= 63


# --- A-labels coming back off the wire ---------------------------------


def test_an_a_label_may_arrive_in_any_case() -> None:
    # RFC 5891 section 5.3 para 1: "first ensuring that the A-label is
    # entirely in lowercase (converting it to lowercase if necessary)".
    assert label_to_ascii("XN--MNCHEN-3YA") == "xn--mnchen-3ya"
    assert to_ascii("XN--MNCHEN-3YA.DE") == "xn--mnchen-3ya.DE"


@pytest.mark.parametrize(
    ("label", "message"),
    [
        ("xn--", "A-label length"),  # prefix with nothing in it
        ("xn--" + "z" * 59 + "9", "A-label length"),  # 63+1 total
        ("xn--a-", "pure-ASCII label"),  # section 5 para 5 of RFC 3492: a
        # string Punycode would terminate right after the delimiter is a
        # pure-basic U-label, "but IDNA forbids such strings from being
        # encoded" -- so this is a Fake A-label (RFC 5890 section 2.3.1
        # para 5) wearing a prefix
        ("xn--abc", "control"),  # decodes to U+0080-something: legal at
        # the codec, no label character at the IDNA layer
        ("xn--9", "unexpected end of input"),  # Punycode's own failure,
        # the "superficial" half of RFC 5891 section 4.2.1 para 2
    ],
)
def test_fake_a_labels_are_rejected(label: str, message: str) -> None:
    with pytest.raises(IdnaError, match=message):
        label_to_ascii(label)


def test_presentation_direction_round_trips() -> None:
    assert to_unicode("xn--mnchen-3ya.de") == "m\u00fcnchen.de"
    assert to_unicode(to_ascii("b\u00fccher.example")) == "b\u00fccher.example"


def test_presentation_direction_passes_through_what_it_cannot_read() -> None:
    # RFC 5891 section 5.3 para 2 asks only that a bad label be recognized
    # as not-an-A-label; presentation must not fail on zone data.
    assert label_to_unicode("xn--9") == "xn--9"  # already lowercase
    assert label_to_unicode("XN--ABC") == "xn--abc"  # folded, still broken
    assert label_to_unicode("example") == "example"  # not an XN-label
    assert to_unicode("example.com") == "example.com"


# --- integration: names and the CLI -------------------------------------


def test_from_unicode_is_the_wire_boundary() -> None:
    name = DomainName.from_unicode("M\u00fcnchen.de.")
    assert name.labels()[0] == b"xn--mnchen-3ya"
    assert bytes(name) == b"\x0exn--mnchen-3ya\x02de\x00"


def test_from_unicode_can_be_strict() -> None:
    with pytest.raises(IdnaError):
        DomainName.from_unicode("M\u00fcnchen.de", map_ascii_case=False)
    # A name already in A-label form needs no folding at all, strict or
    # otherwise.
    strict = DomainName.from_unicode("XN--MNCHEN-3YA.de", map_ascii_case=False)
    assert str(strict) == "xn--mnchen-3ya.de"


def test_a_plain_ascii_query_name_uses_the_cli_fold() -> None:
    # The CLI is a lookup application: the ASCII-only equivalence of
    # RFC 5890 section 2.3.2.4 is its default, and the wire layer's
    # identity is folded anyway (names.py).
    assert str(cli._qname_from_arg("EXAMPLE.com")) == "example.com"


def test_the_cli_helper_punycodes_and_explains_rejections() -> None:
    assert str(cli._qname_from_arg("m\u00fcnchen.de")) == "xn--mnchen-3ya.de"
    with pytest.raises(SystemExit, match="unassigned"):
        cli._qname_from_arg("\u0378.de")
