import struct
from .common import NdrCommon
from ..uuid import bin_to_str, CLSID_SZ
from .objref import ObjRef
from .objref_standard import ObjRefStandard


class PropsOutInfo(NdrCommon):

    FMT1_32 = '<LLLLL'
    FMT1_32_SZ = struct.calcsize(FMT1_32)

    FMT1_64 = '<LQQQL'
    FMT1_64_SZ = struct.calcsize(FMT1_64)

    FMT2_32 = '<LLLLLL'
    FMT2_32_SZ = struct.calcsize(FMT2_32)

    FMT2_64 = '<LLLQLL'
    FMT2_64_SZ = struct.calcsize(FMT2_64)

    def __init__(self, data: bytes):
        offset = 0
        self.read_common(data, offset)
        offset += self.COMMON_SZ
        self.read_private(data, offset)
        offset += self.PRIVATE_SZ

        (
            c_ifs,
            referent_id1,
            referent_id2,
            referent_id3,
            c_ifs,
        ) = struct.unpack_from(self.FMT1_32, data, offset=offset)
        offset += self.FMT1_32_SZ

        self.piids = []
        for _ in range(c_ifs):
            piid = bin_to_str(data, offset)
            offset += CLSID_SZ
            self.piids.append(piid)

        # TODO: the is a HRESULT
        (
            n_result,
            hr_result,
            n_result,
            referent_id4,
            ul_cnt_data_mi,
            ul_cnt_data_ma,
        ) = struct.unpack_from(self.FMT2_32, data, offset=offset)
        offset += self.FMT2_32_SZ

        self.objref: ObjRefStandard =\
            ObjRef.from_data(data, offset, ul_cnt_data_ma)
