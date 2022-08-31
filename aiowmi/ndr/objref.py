"""OBJREF_CUSTUM

See: 2.2.18.6, OBJREF_CUSTOM
"""
import struct
from typing import Union, TYPE_CHECKING
from ..uuid import bin_to_str, CLSID_SZ
from .const import FLAGS_OBJREF_CUSTOM
from .const import FLAGS_OBJREF_EXTENDED
from .const import FLAGS_OBJREF_STANDARD

if TYPE_CHECKING:
    from .objref_standard import ObjRefStandard
    from .objref_custom import ObjRefCustom


class ObjRef:

    OBJREF_FMT = '<LL'
    OBJREF_FMT_SZ = struct.calcsize(OBJREF_FMT)

    OBJREF_SZ = OBJREF_FMT_SZ + CLSID_SZ

    def read_objref(self, data: bytes, offset: int):
        (
            self.signature,
            self.flags,
        ) = struct.unpack_from(self.OBJREF_FMT, data, offset=offset)
        offset += self.OBJREF_FMT_SZ

        self.iid = bin_to_str(data, offset=offset)
        offset += CLSID_SZ  # iid size

    def get_data(self) -> bytes:
        return struct.pack(
            self.OBJREF_FMT,
            self.signature,
            self.flags,
        ) + self.iid + self.clsid

    @classmethod
    def from_data(cls, data: bytes, offset: int, size: int) \
            -> Union['ObjRefStandard', 'ObjRefCustom']:
        (
            signature,
            flags,
        ) = struct.unpack_from(cls.OBJREF_FMT, data, offset=offset)

        if flags & FLAGS_OBJREF_STANDARD:
            from .objref_standard import ObjRefStandard
            return ObjRefStandard.from_data(data, offset, size)

        if flags & FLAGS_OBJREF_CUSTOM:
            from .objref_custom import ObjRefCustom
            return ObjRefCustom.from_data(data, offset, size)

        if flags & FLAGS_OBJREF_EXTENDED:
            raise NotImplementedError('OBJREF_EXTENDED not implemented yet')
            from .objref_extended import ObjRefExtended
            return ObjRefExtended.from_data(data, offset, size)

        assert 0, f'unsupported ObjRef (flags: {flags})'
