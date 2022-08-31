import struct
from .orpcthat import ORPCTHAT
from .objref_standard import ObjRefStandard
from .interface import NdrInterface
from .objref import ObjRef
from ..tools import pad
from ..uuid import uuid_to_bin
from uuid import uuid4


class GetSmartEnumResponse(NdrInterface):

    FMT1_32 = '<LLL'
    FMT1_64 = '<QLL'

    FMT1_32_SZ = struct.calcsize(FMT1_32)

    def __init__(self, data: bytes):
        self.orpcthat, offset = ORPCTHAT.from_data(data, offset=0)

        # activation_blobs
        (
            self.referent_id,
            ul_cnt_data_mi,
            ul_cnt_data_ma,
        ) = struct.unpack_from(self.FMT1_32, data, offset=offset)
        offset += self.FMT1_32_SZ

        self.objref: ObjRefStandard =\
            ObjRef.from_data(data, offset, ul_cnt_data_ma)

        offset += ul_cnt_data_ma + pad(ul_cnt_data_ma)
        self.error_code, = struct.unpack_from('<L', data, offset)

        # generate a random proxy guid
        self.proxy_guid = uuid_to_bin(str(uuid4()))

        assert self.error_code == 0, f'error code: {self.error_code}'

    def get_ipid(self):
        return self.objref.ipid
