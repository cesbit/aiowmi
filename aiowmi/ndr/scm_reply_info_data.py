import struct
from .common import NdrCommon
from ..tools import read_string_bindings
from ..uuid import bin_to_str, CLSID_SZ


class ScmReplyInfoData(NdrCommon):

    FMT1_32 = '<LLQL'
    FMT1_32_SZ = struct.calcsize(FMT1_32)

    FMT1_64 = '<LQQQ'
    FMT1_64_SZ = struct.calcsize(FMT1_64)

    FMT2 = '<LHHLHH'
    FMT2_SZ = struct.calcsize(FMT2)

    def __init__(self, data: bytes):
        offset = 0
        self.read_common(data, offset)
        offset += self.COMMON_SZ
        self.read_private(data, offset)
        offset += self.PRIVATE_SZ

        (
            pdw_reserverd,
            referent_id1,
            self.oxid,
            referent_id2,
        ) = struct.unpack_from(self.FMT1_32, data, offset=offset)
        offset += self.FMT1_32_SZ

        self.ipid_rem_unknown = bin_to_str(data, offset)
        offset += CLSID_SZ

        (
            self.authn_hint,
            version_major,
            version_minor,
            reserved,
            self.w_num_entries,
            self.w_security_offset,
        ) = struct.unpack_from(self.FMT2, data, offset=offset)
        offset += self.FMT2_SZ

        self.str_bindings, offset = read_string_bindings(data, offset=offset)
