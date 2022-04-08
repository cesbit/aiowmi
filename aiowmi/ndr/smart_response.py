import struct
from typing import OrderedDict, Dict
from .class_part import ClassPart
from .next_response import NextResponse
from .object_block import ObjectBlock
from .orpcthat import ORPCTHAT
from .wbem_datapacket_object import WbemDatapacketObject


class SmartResponse(NextResponse):

    FMT1_32 = '<LLLLL'
    FMT1_64 = '<LLQLL'
    FMT1_32_SZ = struct.calcsize(FMT1_32)
    FMT1_64_SZ = struct.calcsize(FMT1_64)

    FMT2_32 = '<LLLBBLLLLL'
    FMT2_32_SZ = struct.calcsize(FMT2_32)

    def __init__(self, data: bytes, class_parts: Dict[str, ClassPart]):
        self.orpcthat, offset = ORPCTHAT.from_data(data, offset=0)
        (
            pu_returned,
            pdw_buff_size,
            referent_id,
            buff_sz,
            byte_ordering,
        ) = struct.unpack_from(self.FMT1_32, data, offset=offset)
        offset += self.FMT1_32_SZ

        assert data[offset: offset+8] == b'WBEMDATA'
        offset += 8

        (
            header1_size,
            data1_size,
            dw_flags,
            b_version,
            b_packettype,
            header2_size,
            data2_size,
            header3_size,
            data3_size,
            dw_num_objects,
        ) = struct.unpack_from(self.FMT2_32, data, offset=offset)
        offset += self.FMT2_32_SZ

        assert b_packettype == 1, 'type must be 0x1 = IWbemWCOSmartEnum::Next'

        # Buffer contains a WBEM_DATAPACKET_OBJECT, 2.2.14.1 MS-WMI
        self._obj_block, offset = \
            WbemDatapacketObject.from_data(data, offset, class_parts)

    def _get_object_block(self) -> ObjectBlock:
        return self._obj_block
