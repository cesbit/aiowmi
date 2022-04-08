import struct
from typing import Tuple, Dict
from ..uuid import CLSID_SZ, bin_to_str
from .class_part import ClassPart
from .object_block import ObjectBlock
from .wbem_object import WbemObject


class WbemDatapacketObject:

    FMT = '<LLBLL'
    FMT_SZ = struct.calcsize(FMT)

    @staticmethod
    def from_data(
            data: bytes,
            offset: int,
            class_parts: Dict[str, ClassPart]) -> Tuple[WbemObject, int]:

        (
            dw_size_of_header0,
            dw_size_of_data0,

            # Here starts the WbemObjectInstance / WbemObjectNoClass
            b_object_type,
            dw_size_of_header1,
            dw_size_of_data1,
        ) = struct.unpack_from(WbemDatapacketObject.FMT, data, offset=offset)
        offset += WbemDatapacketObject.FMT_SZ

        clsid = bin_to_str(data, offset=offset)
        offset += CLSID_SZ

        class_part = None if b_object_type == 2 else class_parts[clsid]

        # b_object_type == 2 means the data contains the class_part
        # b_object_type == 3 means we must already have a class_part
        assert (
            (b_object_type == 2 and class_part is None) or
            (b_object_type == 3 and class_part is not None)
        ), f'object type: {b_object_type} and class_part: {class_part}'

        obj_block, offset = ObjectBlock.from_data(data, offset, class_part)

        if b_object_type == 2:
            class_parts[clsid] = obj_block.class_part

        return obj_block, offset
