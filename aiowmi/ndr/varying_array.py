import struct
from ..tools import pad
from .objref import ObjRef


class VaryingArray:

    FMT1_32 = '<LLL'
    FMT1_64 = '<QQQ'

    FMT1_32_SZ = struct.calcsize(FMT1_32)

    @classmethod
    def from_data(cls, data: bytes, offset: int) -> 'VaryingArray':
        self = cls()
        (
            self.referent_id,
            ndata,
            ndata,
        ) = struct.unpack_from(self.FMT1_32, data, offset)
        offset += cls.FMT1_32_SZ
        end = offset+ndata
        self.objref = ObjRef.from_data(data, offset, end)

        return self, end + pad(ndata)
