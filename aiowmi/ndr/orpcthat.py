"""ORPCTHAT

See MS-DCOM, 2.2.13.4
"""
import struct
from typing import Tuple


class ORPCTHAT:

    FMT32 = '<LL'
    FMT64 = '<LQ'

    FMT32_SZ = struct.calcsize(FMT32)
    FMT64_SZ = struct.calcsize(FMT64)

    EXT = '<LL'

    EXT_SZ = struct.calcsize(EXT)

    EXT32 = '<LL'
    EXT64 = '<LL'

    EXT32_SZ = struct.calcsize(EXT32)
    EXT64_SZ = struct.calcsize(EXT64)

    @classmethod
    def from_data(cls, data: bytes, offset: int = 0) -> Tuple['ORPCTHAT', int]:
        orpcthat = cls()

        orpcthat.flags, extensions = struct.unpack_from(
            cls.FMT32,
            data,
            offset=offset)
        offset += cls.FMT32_SZ

        if extensions:
            assert 0, 'extensions are not implemented correctly (yet)'
            (
                size,
                reserved,
            ) = struct.unpack_from(cls.EXT, data, offset=offset)
            offset += cls.EXT_SZ
            for _ in range(size):
                referent_id, = struct.unpack_from('<L', data, offset=offset)
                offset += 4  # referent_id
                if referent_id:
                    offset += 16  # GUID
                    sz, = struct.unpack_from('<L', data, offset=offset)
                    offset += 4  # What to do with sz?

        return orpcthat, offset
