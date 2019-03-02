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

    let = set(string.ascii_letters.encode('ascii'))
    digit = set(string.digits.encode('ascii'))
    let_dig = set((string.ascii_letters + string.digits).encode('ascii'))
    let_dig_hyp = set((string.ascii_letters + string.digits + '-').encode('ascii'))

    def __init__(self, name, buffer=None, offset=None):
        """
        DNS Label encoder/decoder

        :param name: A traditional domain.name string
        :param buffer: The packet or buffer that the label originated, for referencing the original encoding
        :param offset: The offset into buffer that the label was read
        :param offset: The offset into buffer that the label was read
        """
        try:
            assert isinstance(name, str)
        except:
            pass
        self.name = name
        self.buffer = buffer
        self.offset = offset

    def hierarchy(self):
        labels = self.name.split('.')
        return [self.root_label()] + [self.__class__('.'.join(labels[-i:])) for i in range(1, len(labels) + 1)]

    @classmethod
    def parse_from(cls, buffer, offset=0):
        previousOffsets = []
        labels = []
        nameLength = 0

        final = None

        while (buffer[offset]):
            assert offset not in previousOffsets
            previousOffsets.append(offset)
            if buffer[offset] & 0b11000000:
                if final is None:
                    final = offset + 2
                offset = int.from_bytes(buffer[offset:][:2], 'big') & 0b0011111111111111
                assert 0 <= offset <= len(buffer)
                assert buffer[offset] < 64
                continue

            length = buffer[offset]
            offset += 1
            assert length < 64
            assert offset + length < len(buffer)

            label = buffer[offset:][:length]
            offset += length

            assert label[0] in cls.let  # Must begin with a letter
            assert label[-1] in cls.let_dig  # Must end with letter or digit
            assert cls.let_dig_hyp.issuperset(label[1:][:-1])  # Inner portion can be letter digit hyphen

            nameLength += length
            assert nameLength < 256

            labels.append(label.decode('ascii'))

        else:
            offset += 1
            return cls('.'.join(labels), buffer, offset), final or offset

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
        # https://tools.ietf.org/html/rfc3490
        parts = self.name.encode('ascii').split(b'.')
        assert b'' not in parts[:-1]
        return b''.join([(int.to_bytes(len(label), 1, 'big') if len(label) < 64
                          else int.to_bytes(0b1100000000000000 | len(label), 2, 'little')) + label
                         for label in parts if label]) + bytes([0])

    def __str__(self):
        return str(self.name)

    def __repr__(self):
        return repr(self.name)

    def __ne__(self, other):
        return self.name.upper() != other.name.upper()

    def __eq__(self, other):
        try:
            return self.name.upper() == other.name.upper()
        except:
            pass

    def __hash__(self):
        return self.name.upper()

    @classmethod
    def root_label(cls):
        return cls('.')
