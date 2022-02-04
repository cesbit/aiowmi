import struct
from typing import Union
from ..tools import gen_referent_id, get_null, pad


class WORDSTR:

    FMT32 = '<LLLL'
    FMT64 = '<QQQQ'

    FMT32_SZ = struct.calcsize(FMT32)

    FMT32_NULL = '<L'
    FMT64_NULL = '<Q'

    def __init__(self, inp: Union[str, bytes, None]):
        if isinstance(inp, bytes):
            assert 0
            pass
        else:
            self.string = inp  # None or string

    def get_data(self) -> bytes:
        if self.string is None:
            return get_null()

        data = self.string + '\x00'
        data = data.encode('utf-16le')

        padding = pad(len(data))
        n = len(data)

        maximum_count = actual_count = n // 2
        referent_id = gen_referent_id()

        return struct.pack(
            self.FMT32,
            referent_id,
            maximum_count,
            n,
            actual_count) + data + padding*b'\xbf'
