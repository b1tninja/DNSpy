import string


class DomainName:
    """
    <domain> ::= <subdomain> | " "

    <subdomain> ::= <label> | <subdomain> "." <label>

    <label> ::= <letter> [ [ <ldh-str> ] <let-dig> ]

    <ldh-str> ::= <let-dig-hyp> | <let-dig-hyp> <ldh-str>

    <let-dig-hyp> ::= <let-dig> | "-"

    <let-dig> ::= <letter> | <digit>

    <letter> ::= any one of the 52 alphabetic characters A through Z in
    upper case and a through z in lower case

    <digit> ::= any one of the ten digits 0 through 9

    Note that while upper and lower case letters are allowed in domain
    names, no significance is attached to the case.  That is, two names with
    the same spelling but different case are to be treated as if identical.

    The labels must follow the rules for ARPANET host names.  They must
    start with a letter, end with a letter or digit, and have as interior
    characters only letters, digits, and hyphen.  There are also some
    restrictions on the length.  Labels must be 63 characters or less.

    """

    let = set(string.ascii_letters.encode("ascii"))
    digit = set(string.digits.encode("ascii"))
    let_dig = set((string.ascii_letters + string.digits).encode("ascii"))
    let_dig_hyp = set((string.ascii_letters + string.digits + "-").encode("ascii"))

    def __init__(self, name, buffer=None, offset=None):
        """
        DNS Label encoder/decoder

        :param name: A traditional ``domain.name`` string. A trailing ``.`` is
            the *root terminator* and marks the name as absolute (FQDN); a
            name without it is *relative* and may be promoted to absolute by
            appending a DNS suffix — see :meth:`qualify`.
        :param buffer: The packet or buffer that the label originated, for referencing the original encoding
        :param offset: The offset into buffer that the label was read
        """
        try:
            assert isinstance(name, str)
        except Exception:
            pass
        self.name = name
        self.buffer = buffer
        self.offset = offset

    @property
    def is_absolute(self):
        """Whether this name carries the root terminator (a trailing ``.``).

        On the wire, every name is absolute (terminated by the zero-length root
        label). In presentation form, a trailing ``.`` explicitly anchors the
        name at the root and prevents any DNS suffix from being assumed; a
        name without it is relative and a suffix may be applied via
        :meth:`qualify`. The bare root (``"."`` or ``""``) is absolute.
        """
        s = self.name or ""
        return s == "" or s.endswith(".")

    @property
    def terminated(self):
        """Alias of :attr:`is_absolute`, reading as "has a root terminator"."""
        return self.is_absolute

    def qualify(self, dns_suffix=None):
        """Return an absolute :class:`DomainName`, applying a DNS suffix if needed.

        If this name is already absolute, ``self`` is returned unchanged — the
        trailing root terminator on the wire prevents any suffix from being
        assumed. Otherwise the result is composed of this name's labels, then
        ``dns_suffix`` if one is supplied, then the root terminator. With no
        ``dns_suffix``, the relative name is simply anchored at the root.

        The decision of *which* suffix to assume for a relative name is the
        resolver's responsibility (see :attr:`aiodns.resolver.Resolver.dns_suffix`);
        :class:`DomainName` itself is suffix-agnostic.
        """
        if self.is_absolute:
            return self
        base = (self.name or "").rstrip(".")
        sfx = str(dns_suffix).strip().rstrip(".") if dns_suffix is not None else ""
        if base and sfx:
            qualified = base + "." + sfx + "."
        elif base:
            qualified = base + "."
        elif sfx:
            qualified = sfx + "."
        else:
            qualified = "."
        return self.__class__(qualified)

    def hierarchy(self):
        labels = self.name.split(".")
        return [self.root_label()] + [
            self.__class__(".".join(labels[-i:])) for i in range(1, len(labels) + 1)
        ]

    @classmethod
    def parse_from(cls, buffer, offset=0):
        previousOffsets = []
        labels = []
        nameLength = 0

        final = None

        while buffer[offset]:
            assert offset not in previousOffsets
            previousOffsets.append(offset)
            if buffer[offset] & 0b11000000:
                if final is None:
                    final = offset + 2
                offset = int.from_bytes(buffer[offset:][:2], "big") & 0b0011111111111111
                assert 0 <= offset <= len(buffer)
                assert buffer[offset] < 64
                continue

            length = buffer[offset]
            offset += 1
            assert length < 64
            assert offset + length <= len(buffer)

            label = buffer[offset:][:length]
            offset += length

            # On wire, labels may start with a digit (e.g. in-addr.arpa / ip6.arpa reverse trees).
            assert label[0] in cls.let_dig  # letter or digit
            assert label[-1] in cls.let_dig  # Must end with letter or digit
            assert cls.let_dig_hyp.issuperset(label[1:][:-1])  # Inner portion can be letter digit hyphen
            nameLength += length
            assert nameLength < 256

            labels.append(label.decode("ascii"))

        else:
            offset += 1
            # Wire form is always absolute (terminated by the zero-length root
            # label); reflect that in the presentation form so :attr:`is_absolute`
            # and equality see it as such.
            presentation = ".".join(labels) + "." if labels else "."
            return cls(presentation, buffer, offset), final or offset

    # @classmethod
    # def parse(cls, stream):
    #     start = stream.tell()
    #     previousOffsets = []
    #     labels = []
    #     nameLength = 0
    #
    #     while (stream.peek(1)):
    #         offset = stream.tell()
    #         assert offset not in previousOffsets
    #         previousOffsets.append(offset)
    #         if stream.peek(1) & 0b11000000:
    #             stream.seek(stream.read(2) & 0b0011111111111111)
    #             # assert 0 <= offset <= len(stream.__sizeof__())
    #             assert stream.peek(1) < 64
    #             continue
    #
    #         length = stream.read(1)
    #         assert length < 64
    #         # assert offset + length < len(stream)
    #
    #         label = stream.read(length)
    #
    #         assert label[0] in cls.let  # Must begin with a letter
    #         assert label[-1] in cls.let_dig  # Must end with letter or digit
    #         assert cls.let_dig_hyp.issuperset(label[1:][:-1])  # Inner portion can be letter digit hyphen
    #
    #         nameLength += length
    #         labels.append(label.decode('ascii'))
    #         assert nameLength + len(labels) < 256
    #
    #     else:
    #         stream.read(1)
    #         return cls('.'.join(labels), stream, offset=start)
    #
    def __bytes__(self):
        # TODO support https://tools.ietf.org/html/rfc3490
        # RFC 1035 §3.1: each label is a length-prefixed byte string and the
        # name is terminated by the zero-length root label. The trailing ``.``
        # in presentation form is the root terminator and is not itself a
        # label — strip it before splitting so we don't emit a phantom
        # zero-length label *before* the actual terminator (which would
        # double-null the wire form and shift QTYPE/QCLASS by one byte).
        name = (self.name or "").rstrip(".")
        if not name:
            return bytes([0])
        parts = name.encode("ascii").split(b".")
        assert b"" not in parts
        return b"".join(
            [
                (
                    int.to_bytes(len(label), 1, "big")
                    if len(label) < 64
                    else int.to_bytes(0b1100000000000000 | len(label), 2, "little")
                )
                + label
                for label in parts
            ]
        ) + bytes([0])

    def __str__(self):
        return str(self.name)

    def __repr__(self):
        return repr(self.name)

    def _labels(self) -> tuple[str, ...]:
        """Case-folded label tuple for the DNS name; trailing root terminator is not significant.

        On the wire every name is fully qualified (RFC 1035 §3.1), so equality
        is wire-form based: ``com`` and ``com.`` denote the same name and
        produce the same tuple. The trailing ``.`` is meaningful only as the
        root terminator that tells a *resolver* not to assume a DNS suffix
        (see :meth:`qualify` and :attr:`aiodns.resolver.Resolver.dns_suffix`).
        ASCII case is also ignored. The root (``"."`` and empty) is ``()``.
        """
        s = (self.name or "").strip().rstrip(".")
        return tuple(p.upper() for p in s.split(".") if p) if s else ()

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            other = DomainName(other)
        if not isinstance(other, DomainName):
            return NotImplemented
        return self._labels() == other._labels()

    def __hash__(self) -> int:
        return hash(self._labels())

    @classmethod
    def root_label(cls):
        return cls(".")
