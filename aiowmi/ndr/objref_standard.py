"""OBJREF_CUSTUM

See: 2.2.18.6, OBJREF_CUSTOM
"""
import struct

from ..uuid import bin_to_str, CLSID_SZ
from .objref import ObjRef


class ObjRefStandard(ObjRef):

    __slots__ = (
        'std_flags',
        'c_public_refs',
        'oxid',
        'oid',
        'ipid',
        'sa_res_addr')

    STANDARD_FMT = '<LLQQ'
    STANDARD_FMT_SZ = struct.calcsize(STANDARD_FMT)

    @classmethod
    def from_data(cls, data: bytes, offset: int, size=int) \
            -> 'ObjRefStandard':
        end = offset+size
        self = cls()

        self.read_objref(data, offset)
        offset += cls.OBJREF_SZ

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

        # This is a DualString (see dualstring.py)
        self.sa_res_addr = data[offset:end]
        return self

    def get_data(self) -> bytes:
        return super().get_data() + struct.pack(
            self.STANDARD_FMT,
            self.std_flags,
            0,
            self.oxid,
            self.oid
        ) + self.sa_res_addr
