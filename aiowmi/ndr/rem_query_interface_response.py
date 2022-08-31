import struct
from ..exceptions import ServerNotOptimized
from .interface import NdrInterface
from .objref_std import ObjRefStd
from .orpcthat import ORPCTHAT


class RemQueryInterfaceResponse(NdrInterface):
    FMT1_32 = '<LlLL'
    FMT1_64 = '<QlLL'

    FMT1_32_SZ = struct.calcsize(FMT1_32)

    def __init__(self, data: bytes):
        self.orpcthat, offset = ORPCTHAT.from_data(data, offset=0)

        (
            self.referent_id,
            n_size,
            h_result,
            pad,
        ) = struct.unpack_from(self.FMT1_32, data, offset)
        offset += self.FMT1_32_SZ

        if h_result:
            raise ServerNotOptimized('Server is not optimized')

        self.objref, offset = ObjRefStd.from_data(data, offset)

        self.error_code, = struct.unpack_from('<L', data, offset)
        assert self.error_code == 0, f'error code: {self.error_code}'

    def get_ipid(self):
        return self.objref.ipid
