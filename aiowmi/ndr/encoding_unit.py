import struct
from .object_block import ObjectBlock


class EncodingUnit:

    FMT = '<LL'
    FMT_SZ = struct.calcsize(FMT)

    def __init__(self, data):
        offset = 0
        (
            self.signature,
            encoding_len,
        ) = struct.unpack_from(self.FMT, data, offset=offset)
        offset += self.FMT_SZ

        self.object_block, offset = ObjectBlock.from_data(data, offset)
