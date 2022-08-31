import struct
from ..tools import pad
from .orpcthat import ORPCTHAT
from .objref_standard import ObjRefStandard
from .interface import NdrInterface


class NTLMLoginResponse(NdrInterface):

    FMT1_32 = '<LLL'
    FMT1_64 = '<QLL'

    FMT1_32_SZ = struct.calcsize(FMT1_32)

    def __init__(self, data: bytes):
        self.orpcthat, offset = ORPCTHAT.from_data(data, offset=0)

        # activation_blobs

        (
            self.referent_id,
            _,
            size
        ) = struct.unpack_from(self.FMT1_32, data, offset)
        offset += self.FMT1_32_SZ

        self.objref = ObjRefStandard.from_data(data, offset, size)
        offset += size + pad(size)

        self.error_code, = struct.unpack_from('<L', data, offset)
        assert self.error_code == 0, f'error code: {self.error_code}'

    def get_ipid(self):
        return self.objref.ipid
