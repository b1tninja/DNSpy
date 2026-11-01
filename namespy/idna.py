"""IDNA2008 label processing: punycode and the A-label boundary.

This module is the boundary between the Unicode a user types and the octets
the DNS carries.  :mod:`namespy.names` stores labels as raw octets and
passes A-labels through untouched (RFC 5890 section 2.3, pinned by
``test_names.py``), which means *somebody* must turn ``muenchen.de`` into
``xn--mnchen-3ya.de`` before the wire and back again before a human reads
it.  Until now that somebody was the caller.

The algorithm is RFC 3492's punycode, transcribed from sections 6.1-6.4
with the section 5 parameter values; the protocol around it -- when a label
may be encoded, which tests a U-label must pass, and the round trip a
decoder owes an A-label -- is RFC 5891 sections 4 and 5, with the label
taxonomy from RFC 5890 section 2.3.

What is *not* here: the character validity tables of RFC 5892.  IDNA2008's
permitted/forbidden/contextual character sets are derived Unicode data, and
this remains a standard-library package, so the table-backed tests are
decided as far as ``unicodedata`` can take them -- unassigned code points
(RFC 5891 section 5.4's "UNASSIGNED"), and a conservative subset of
"DISALLOWED" (controls, separators, private use) -- while the CONTEXTJ and
CONTEXTO rules are left to the DNS itself.  That is not a shortcut: RFC
5891 section 5.4 para 13 tells a lookup application to "rely on the
presence or absence of labels in the DNS" for exactly those labels it
cannot evaluate, and "applications that decline to process a string that
conforms to the rules above ... are not in conformance with this protocol."
"""

from __future__ import annotations

import unicodedata

__all__ = [
    "ACE_PREFIX",
    "IdnaError",
    "label_to_ascii",
    "label_to_unicode",
    "punycode_decode",
    "punycode_encode",
    "to_ascii",
    "to_unicode",
]

# RFC 3492 section 5: Punycode's Bootstring parameter values.
_BASE = 36
_TMIN = 1
_TMAX = 26
_SKEW = 38
_DAMP = 700
_INITIAL_BIAS = 72
_INITIAL_N = 128
_DELIMITER = "-"

# RFC 3492 section 6.4: "For IDNA, 26-bit unsigned integers are sufficient
# to handle all valid IDNA labels without overflow ... However, overflow
# handling is necessary because the inputs are not necessarily valid IDNA
# labels."  Erratum 265 reads maxint as "the maximum value of an integer
# variable"; Python integers have no maximum, so the spec's own 26-bit
# bound is the honest width to check against -- it rejects nothing real and
# everything that could run away.
_MAXINT = (1 << 26) - 1

# RFC 3492 section 5: code points are "integers in the range 0..10FFFF
# (but not D800..DFFF, which are reserved for use by the UTF-16 encoding)".
_MAX_CODE_POINT = 0x10FFFF

#: RFC 5891 section 4.4: "the ACE prefix 'xn--' added at the beginning".
ACE_PREFIX = "xn--"


class IdnaError(ValueError):
    """A label is not a valid U-label, A-label, or punycode string."""


def _digit_value(ch: str) -> int | None:
    """RFC 3492 section 5: A-Z and a-z are 0..25, 0-9 is 26..35.  One table
    serves both cases because "a decoder MUST recognize the letters in both
    uppercase and lowercase forms" (section 5 para 6)."""
    code = ord(ch)
    if 0x41 <= code <= 0x5A:
        return code - 0x41
    if 0x61 <= code <= 0x7A:
        return code - 0x61
    if 0x30 <= code <= 0x39:
        return code - 0x30 + 26
    return None


def _digit_char(value: int) -> str:
    """The encoder's half of the same table.  Lowercase always: section 5
    para 6 asks an encoder to pick one case, and RFC 5890 section 2.3.1
    para 4 settles it -- "A-labels should be produced only in lowercase"."""
    return chr(0x61 + value) if value < 26 else chr(0x30 + value - 26)


def _adapt(delta: int, numpoints: int, firsttime: bool) -> int:
    """RFC 3492 section 6.1, line by line."""
    delta //= _DAMP if firsttime else 2
    delta += delta // numpoints
    k = 0
    while delta > ((_BASE - _TMIN) * _TMAX) // 2:
        delta //= _BASE - _TMIN
        k += _BASE
    return k + ((_BASE - _TMIN + 1) * delta) // (delta + _SKEW)


def punycode_encode(text: str) -> str:
    """RFC 3492 section 6.3.  No ACE prefix here -- that is RFC 5891
    section 4.4's work, and keeping it out means the codec round-trips on
    its own."""
    for ch in text:
        code = ord(ch)
        if code > _MAX_CODE_POINT or 0xD800 <= code <= 0xDFFF:
            raise IdnaError(
                f"code point U+{code:04X} is outside 0..10FFFF excluding"
                " surrogates (RFC 3492 section 5)"
            )
    basic = [ch for ch in text if ord(ch) < 0x80]
    out = list(basic)  # literals copy in order, original case and all
    h = b = len(basic)
    if b:
        out.append(_DELIMITER)  # "followed by a delimiter if b > 0"
    n, delta, bias = _INITIAL_N, 0, _INITIAL_BIAS
    while h < len(text):
        # "the minimum non-basic code point >= n": every code point at or
        # above 128 is non-basic, so section 6.3 para 3 elides the qualifier.
        m = min(ord(ch) for ch in text if ord(ch) >= n)
        if m - n > (_MAXINT - delta) // (h + 1):  # section 6.4's A + B*C test
            raise IdnaError("punycode encode: delta overflow")
        delta += (m - n) * (h + 1)
        n = m
        for ch in text:
            c = ord(ch)
            if c < n:
                delta += 1
                if delta > _MAXINT:
                    raise IdnaError("punycode encode: delta overflow")
            if c == n:
                q = delta
                k = _BASE
                while True:
                    t = _TMIN if k <= bias else (_TMAX if k >= bias + _TMAX else k - bias)
                    if q < t:
                        break
                    out.append(_digit_char(t + (q - t) % (_BASE - t)))
                    q = (q - t) // (_BASE - t)
                    k += _BASE
                out.append(_digit_char(q))
                bias = _adapt(delta, h + 1, h == b)
                delta = 0
                h += 1
        delta += 1
        # Section 6.3 para 6: n cannot overflow mid-run -- by the time it
        # could, h == len(text) and the procedure is finished anyway.
        n += 1
    return "".join(out)


def punycode_decode(text: str) -> str:
    """RFC 3492 section 6.2.  An encoded string is ASCII by construction
    (section 6.2 copies literals "fail on any non-basic code point", and its
    digits are ASCII letters and numbers), so anything else fails at the
    gate -- as does every malformed tail: section 6.2 para 3-4 make the
    decoder's failures the only way two inputs could mean the same string,
    and para 3 of section 6.4 notes the decoder "cannot produce the same
    output for two distinct inputs" when it fails on them as shown."""
    if not text.isascii():
        raise IdnaError("punycode decode: non-ASCII character in an encoded string")
    n, i, bias = _INITIAL_N, 0, _INITIAL_BIAS
    out: list[int] = []
    cut = text.rfind(_DELIMITER)
    if cut > 0:
        out = [ord(ch) for ch in text[:cut]]  # all basic, by the gate above
        text = text[cut + 1 :]
    # cut == 0 is deliberately not sliced away: with zero literals consumed,
    # section 6.2 does "not consume one more", so the delimiter stays at the
    # head and the digit loop below fails on it.  No encoder emits that form
    # (section 6.3 writes the delimiter only after copied literals).

    pos = 0
    while pos < len(text):
        oldi, w, k = i, 1, _BASE
        while True:
            if pos >= len(text):
                raise IdnaError("punycode decode: unexpected end of input")
            digit = _digit_value(text[pos])
            pos += 1
            if digit is None:
                raise IdnaError(f"punycode decode: {text[pos - 1]!r} has no digit-value")
            if digit > (_MAXINT - i) // w:  # section 6.4's A + B*C test
                raise IdnaError("punycode decode: index overflow")
            i += digit * w
            t = _TMIN if k <= bias else (_TMAX if k >= bias + _TMAX else k - bias)
            if digit < t:
                break
            if _BASE - t > _MAXINT // w:
                raise IdnaError("punycode decode: weight overflow")
            w *= _BASE - t
            k += _BASE
        bias = _adapt(i - oldi, len(out) + 1, oldi == 0)
        step = i // (len(out) + 1)
        if step > _MAXINT - n:
            raise IdnaError("punycode decode: code point overflow")
        n += step
        i %= len(out) + 1
        # Section 6.2's braced "fail if n is basic" is elided per section
        # 6.2 para 2: initial_n exceeds every basic code point and n only
        # climbs.  The top of the range is Punycode's own domain though.
        if n > _MAX_CODE_POINT:
            raise IdnaError(f"punycode decode: U+{n:X} exceeds 10FFFF")
        if 0xD800 <= n <= 0xDFFF:
            raise IdnaError(
                "punycode decode: surrogate code points are reserved (RFC 3492 section 5)"
            )
        out.insert(i, n)
        i += 1
    return "".join(chr(c) for c in out)


def _fold_ascii_case(text: str) -> str:
    """Fold A-Z onto a-z and nothing else.  The DNS's own equivalence is
    ASCII-only (RFC 5890 section 2.3.2.4 counts "uppercase and lowercase"
    of that character list equivalent), and so is this package's name
    identity; str.lower() is not a substitute -- it can *grow* a label
    (U+0130 alone takes two characters when lowercased)."""
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in text)


def _check_u_label(label: str) -> None:
    """The tests RFC 5891 puts a U-label through, as far as the standard
    library can decide them without RFC 5892's tables (see the module
    docstring for exactly which tests that leaves out)."""
    if not label:
        raise IdnaError("empty U-label (RFC 5890 section 2.3.2.1)")
    # RFC 5891 section 4.1: "By the time a string enters the IDNA
    # registration process ... it MUST be in Unicode and in Normalization
    # Form C"; section 5.4 repeats it for lookup.
    if unicodedata.normalize("NFC", label) != label:
        raise IdnaError("U-label is not in NFC (RFC 5891 sections 4.1, 5.4)")
    # IDNA2008 maps nothing on the way up (that is IDNA2003's sin, RFC 5891
    # appendix A), and the RFC 5892 tables put A-Z in DISALLOWED, so an
    # uppercase ASCII letter is simply not a U-label character.  A-labels
    # are lowercase anyway (RFC 5890 section 2.3.1 para 4).
    if any("A" <= c <= "Z" for c in label):
        raise IdnaError(
            "U-label contains ASCII uppercase, which IDNA2008 disallows and"
            " never case-maps; pass map_ascii_case=True if a human typed it"
        )
    # RFC 5891 section 4.2.3.1.
    if label.startswith("-") or label.endswith("-") or label[2:4] == "--":
        raise IdnaError("hyphen restriction (RFC 5891 section 4.2.3.1)")
    # RFC 5891 sections 4.2.3.2, 5.4: no leading combining mark.  The
    # general categories M* are Unicode's definition of one.
    if unicodedata.category(label[0]).startswith("M"):
        raise IdnaError("U-label begins with a combining mark (RFC 5891 section 4.2.3.2)")
    for c in label:
        category = unicodedata.category(c)
        if category == "Cn":
            # RFC 5891 section 5.4: unassigned in "the version of Unicode
            # being used by the application" -- and unicodedata's version
            # *is* the version this application uses.
            raise IdnaError(f"U+{ord(c):04X} is unassigned in this Unicode version")
        if category in ("Cc", "Cs", "Co", "Zl", "Zp", "Zs"):
            # A subset of DISALLOWED that needs no table: controls,
            # surrogates, private use, and every kind of space.
            raise IdnaError(
                f"U+{ord(c):04X} is a control, separator, or private-use"
                " code point (RFC 5891 section 5.4, DISALLOWED subset)"
            )


def _validate_a_label(label: str) -> str:
    """RFC 5891 section 5.3 for an A-label input: lowercase it ("first
    ensuring that the A-label is entirely in lowercase"), punycode-decode
    it, apply section 5.4's tests to the resulting U-label, and require
    that re-encoding reproduce the label exactly -- "the label MUST be
    rejected if the resulting label is not identical to the original."
    The round trip is also section 6.4 paras 5-6's delayed overflow
    detection, so the codec's own failures and Fake A-labels (RFC 5890
    section 2.3.1 para 5) all land in the same rejection."""
    lowered = _fold_ascii_case(label)
    body = lowered[len(ACE_PREFIX) :]
    # RFC 5890 section 2.3.1 para 3: "the portion of an XN-label derived
    # from the Punycode algorithm is limited to no more than 59 ASCII
    # characters" -- 63 minus the four of the prefix.
    if not body or len(lowered) > 63:
        raise IdnaError("A-label length (RFC 5890 section 2.3.1 para 3)")
    decoded = punycode_decode(body)
    _check_u_label(decoded)
    if not any(ord(c) >= 0x80 for c in decoded):
        # RFC 3492 section 5 para 5: an encoding can end with the delimiter
        # "only if the Unicode string consists entirely of basic code
        # points, but IDNA forbids such strings from being encoded".  A
        # pure-ASCII decoding therefore labels a Fake A-label.
        raise IdnaError(
            "A-label decodes to a pure-ASCII label; IDNA never punycodes"
            " one (RFC 3492 section 5 para 5)"
        )
    if punycode_encode(decoded) != body:
        raise IdnaError("A-label does not round-trip (RFC 5891 section 5.3 para 1)")
    return lowered


def label_to_ascii(label: str, *, map_ascii_case: bool = False) -> str:
    """One label in, one wire-ready label out.

    Pure-ASCII labels that are not XN-labels pass through untouched --
    "IDNA never encodes pure ASCII labels" (RFC 3492 section 7.1, on
    example S) -- and the octet-transparent store in :mod:`namespy.names`
    is the authority on everything else ASCII.  An XN-label is validated
    as one; anything else is treated as a U-label candidate and encoded
    per RFC 5891 section 4.4.
    """
    if not label:
        return label  # the root label; there is nothing to encode
    if map_ascii_case:
        label = _fold_ascii_case(label)
    if label.isascii():
        if label[:4].lower() != ACE_PREFIX:
            return label
        return _validate_a_label(label)
    _check_u_label(label)
    encoded = ACE_PREFIX + punycode_encode(label)
    if len(encoded) > 63:  # RFC 5891 section 4.4 para 1, via RFC 5890 2.3.1
        raise IdnaError(f"encoded label is {len(encoded)} characters, over 63")
    return encoded


def label_to_unicode(label: str) -> str:
    """One label in, its U-label out for presentation; labels that are not
    XN-labels pass through, and XN-labels that fail validation come back
    lowercased as written.  A resolver sees zone data it cannot fix, and
    RFC 5891 section 5.3 para 2 asks of such a label only that it be
    recognized as not-one -- raising here would turn a presentation
    nicety into a lookup failure."""
    if not label.isascii() or label[:4].lower() != ACE_PREFIX:
        return label
    try:
        lowered = _validate_a_label(label)
    except IdnaError:
        return _fold_ascii_case(label)
    return punycode_decode(lowered[len(ACE_PREFIX) :])


def to_ascii(domain: str, *, map_ascii_case: bool = False) -> str:
    """Dotted-name form in, dotted-name form out, label by label.

    Splits on ``.`` and does not interpret backslash escapes: this is for
    names a human typed.  :class:`~namespy.names.DomainName`'s own parser
    remains the authority on escaped input.
    """
    return ".".join(
        label_to_ascii(label, map_ascii_case=map_ascii_case) for label in domain.split(".")
    )


def to_unicode(domain: str) -> str:
    """Presentation direction of :func:`to_ascii`: A-labels become
    U-labels where they honestly are one, everything else passes
    through."""
    return ".".join(label_to_unicode(label) for label in domain.split("."))
