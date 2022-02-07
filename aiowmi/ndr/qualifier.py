import struct
from typing import Tuple
from ..cim_type import CimType


class Qualifier:

    FMT = '<LBL'
    FMT_SZ = struct.calcsize(FMT)

    @classmethod
    def from_data(cls, data: bytes, offset: int) -> Tuple['Qualifier', int]:
        self = cls()
        (
            self.name,
            self.flavor,
            self.type,
        ) = struct.unpack_from(cls.FMT, data, offset=offset)
        offset += cls.FMT_SZ

        key = self.type & (~CimType.CIM_ARRAY_FLAG)

        self.value, offset = CimType.get_value(key, data, offset=offset)

        return self, offset
