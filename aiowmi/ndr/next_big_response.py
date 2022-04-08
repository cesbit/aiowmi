import struct
from typing import OrderedDict
from .orpcthat import ORPCTHAT
from .objref_standard import ObjRefStandard
from .activation_blob import ActivationBlob
from .scm_reply_info_data import ScmReplyInfoData
from .props_out_info import PropsOutInfo
from ..tools import is_fqdn
from .varying_array import VaryingArray
from .encoding_unit import EncodingUnit
from .property_info import PropertyInfo
from .next_response import NextResponse
from .object_block import ObjectBlock


class NextBigResponse(NextResponse):

    _FMT1_32 = '<LLL'
    _FMT1_64 = '<QQQ'

    _FMT1_32_SZ = struct.calcsize(_FMT1_32)
    _FMT1_64_SZ = struct.calcsize(_FMT1_64)

    def __init__(self, data: bytes):
        self.orpcthat, offset = ORPCTHAT.from_data(data, offset=0)
        (
            ncount,
            noffset,
            ncount,
        ) = struct.unpack_from(self._FMT1_32, data, offset)
        offset += self._FMT1_32_SZ
        ap_objects = []

        for _ in range(ncount):
            va, offset = VaryingArray.from_data(data, offset)
            encoding_unit = EncodingUnit(va.objref.object_data)
            ap_objects.append(encoding_unit)

        (
            self.pu_returned,
            self.error_code,
        ) = struct.unpack_from('<LL', data, offset)

        assert len(ap_objects) == 1, "only support for a single object block"
        self._obj_block = ap_objects[0].object_block

    def _get_object_block(self) -> ObjectBlock:
        return self._obj_block
