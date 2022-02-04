import struct
from .encoded_string import EncodedString
from .class_part import ClassPart
from .heap import Heap
from .qualifier_set import QualifierSet
from .object_block import ObjectBlock


class EncodingUnit:

    FMT = '<L'
    FMT_SZ = struct.calcsize(FMT)

    def __init__(self, data):
        offset = 0
        (
            self.signature,
        ) = struct.unpack_from(self.FMT, data, offset=offset)
        offset += self.FMT_SZ

        self.object_block, offset = ObjectBlock.from_data(data, offset)
