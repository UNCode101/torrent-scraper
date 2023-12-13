# /usr/bin/env python3
# Based on https://github.com/gazev/bencode (GPLv3 license) as of 2023-12-12


def loads(s):
    """Deserialize ``s`` (``bytes`` or ``bytearray`` instance
    containing a Bencoded document) to a Python object.
    """
    return Decoder(s).decode()


def load(fp):
    """Deserialize ``fp`` (a ``.read()``-supporting file-like object containing
    a Bencoded document) to a Python object.
    """
    return Decoder(fp.read()).decode()


def dumps(obj):
    """Serialize ``obj`` to a Bencode formatted ``str``."""
    return Encoder().encode(obj)


def dump(obj, fp):
    """Serialize ``obj`` as a Bencode formatted stream to ``fp`` (a
    ``.write()``-supporting file-like object).
    """
    fp.write(Encoder().encode(obj))


class BencodeEncodingError(ValueError):
    ...


class Encoder:
    """Simple Bencode encoder <https://en.wikipedia.org/wiki/Bencode>

    Performs the following translations in encoding by default:
    +---------------+-------------------+
    | Python        | Bencode           |
    +===============+===================+
    | int           | integer           |
    +---------------+-------------------+
    | str           | string            |
    +---------------+-------------------+
    | bytes         | string            |
    +---------------+-------------------+
    | list          | list              |
    +---------------+-------------------+
    | dict          | dictionary        |
    +---------------+-------------------+
    """

    @classmethod
    def encode(cls, item) -> bytes:
        """Encode passed item into corresponding Bencode type"""
        if isinstance(item, dict):
            ret = cls.encode_dict(item)
        elif isinstance(item, list):
            ret = cls.encode_list(item)
        elif isinstance(item, int):
            ret = cls.encode_int(item)
        elif isinstance(item, bytes):
            ret = cls.encode_byte_str(item)
        elif isinstance(item, str):
            ret = cls.encode_str(item)
        else:
            raise BencodeEncodingError(f"Unsupported type {type(item)}")

        return ret

    @classmethod
    def encode_int(cls, num: int) -> bytes:
        res = bytearray(b"i")
        res += bytes(str(num), "utf-8")
        res += b"e"

        return bytes(res)

    @classmethod
    def encode_byte_str(cls, string: bytes) -> bytes:
        length = bytes(str(len(string)), "utf-8")

        return length + b":" + string

    @classmethod
    def encode_str(cls, string: str) -> bytes:
        length = bytes(str(len(string)), "utf-8")

        return length + b":" + bytes(string, "utf-8")

    @classmethod
    def encode_list(cls, lst: list) -> bytes:
        res = bytearray(b"l")
        for item in lst:
            res += cls.encode(item)
        res += b"e"

        return bytes(res)

    @classmethod
    def encode_dict(cls, dic: dict) -> bytes:
        res = bytearray(b"d")
        for k, v in dic.items():
            res += cls.encode(k)
            res += cls.encode(v)
        res += b"e"

        return bytes(res)


class BencodeDecodingError(ValueError):
    ...


class Decoder:
    """Simple Bencode decoder <https://en.wikipedia.org/wiki/Bencode>

    Performs the following translations in decoding by default:
    +---------------+-------------------+
    | Bencode       | Python            |
    +===============+===================+
    | integer       | int               |
    +---------------+-------------------+
    | string        | bytes             |
    +---------------+-------------------+
    | list          | list              |
    +---------------+-------------------+
    | dictionary    | dict{string:any}  |
    +---------------+-------------------+
    """

    def __init__(self, data):
        self._data = data
        self._index = 0

        self.decoder_call = {
            b"i": self.decode_int,
            b"l": self.decode_list,
            b"d": self.decode_dict,
            b"0": self.decode_str,
            b"1": self.decode_str,
            b"2": self.decode_str,
            b"3": self.decode_str,
            b"4": self.decode_str,
            b"5": self.decode_str,
            b"6": self.decode_str,
            b"7": self.decode_str,
            b"8": self.decode_str,
            b"9": self.decode_str,
        }

    def _current_byte(self):
        """Peek current byte"""
        return self._data[self._index : self._index + 1]

    def _consume_byte(self):
        """Read byte"""
        ret = self._current_byte()
        self._index += 1

        return ret

    def decode_int(self) -> bytes:
        # discard 'i' begin token
        self._index += 1
        res = bytearray()
        while self._current_byte() != b"e":
            res += self._consume_byte()

        # reject numbers with leading zeros
        if res[0:1] == b"0" and len(res) > 1:
            raise BencodeDecodingError(f"Invalid integer encoding {bytes(res)}")

        # discard 'e' end token
        self._index += 1
        return bytes(int(res))

    def decode_str(self) -> bytes:
        length = 0
        while self._current_byte() != b":":
            # unclosed str length
            if self._current_byte() not in b"0123456789":
                raise BencodeDecodingError(
                    f'Invalid token {self._current_byte()} at index {self._index}, missing ":"?'
                )

            length = length * 10 + ord(self._consume_byte()) - ord("0")
        self._index += 1

        res = bytearray()
        while length > 0:
            res += self._consume_byte()
            length -= 1
        return bytes(res)

    def decode_list(self) -> list:
        # discard 'l' begin token
        self._index += 1
        lst = []
        while self._current_byte() != b"e":
            new_item = self.decode()
            lst.append(new_item)
        # discard 'e' end token
        self._index += 1
        return lst

    def decode_dict(self) -> dict:
        # discard 'd' begin token
        self._index += 1
        dic = {}
        while self._current_byte() != b"e":
            key = self.decode().decode("utf-8")
            value = self.decode()
            dic[key] = value
        # discard 'e' end token
        self._index += 1
        return dic

    def decode(self):
        if self._current_byte() == b"":
            raise BencodeDecodingError(f'Out of bounds read, missing "e"?')

        if self._current_byte() in self.decoder_call:
            return self.decoder_call[self._current_byte()]()
        else:
            raise BencodeDecodingError(
                f"Unexpected token {self._current_byte()} at position {self._index}"
            )

        return item
