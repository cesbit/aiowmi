"""OBJREF_CUSTUM

See: 2.2.18.6, OBJREF_CUSTOM
"""
import struct
from typing import Tuple
from ..uuid import bin_to_str, CLSID_SZ
from .objref import ObjRef


class ObjRefStd(ObjRef):

    __slots__ = (
        'std_flags',
        'c_public_refs',
        'oxid',
        'oid',
        'ipid')

    STANDARD_FMT = '<LLQQ'
    STANDARD_FMT_SZ = struct.calcsize(STANDARD_FMT)

    @classmethod
    def from_data(cls, data: bytes, offset: int) -> Tuple['ObjRefStd', int]:
        self = cls()

        (
            self.std_flags,
            self.c_public_refs,
            self.oxid,
            self.oid,
        ) = struct.unpack_from(cls.STANDARD_FMT, data, offset=offset)

        # 3.2.4.4 Managing Object Lifetime
        # if the public reference counter is 0, then we need to get a new
        # reference (RemAddRef) and release when finished (RemRelease).
        assert self.c_public_refs, 'public reference counter is 0'

        offset += cls.STANDARD_FMT_SZ

        self.ipid = bin_to_str(data, offset=offset)
        offset += CLSID_SZ

        return self, offset
