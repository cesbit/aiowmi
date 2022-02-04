"""ORPCTHIS

See MS-DCOM, 2.2.13.3
"""
import struct
from ..tools import gen_cid
from .com_version import COM_VERSION


class ORPCTHIS:

    EXT32 = '<L'
    EXT64 = '<Q'

    @classmethod
    def get_data(cls, flags: int = 0) -> bytes:
        flags = flags
        reserved = 0
        cid = gen_cid()
        extensions = 0

        return COM_VERSION + struct.pack(
            '<LL',
            flags,
            reserved
        ) + cid + struct.pack(cls.EXT32, extensions)
