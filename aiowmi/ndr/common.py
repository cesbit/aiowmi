import struct
from ..tools import pad8


class NdrCommon:

    COMMON_FMT = '<BBHL'
    COMMON_SZ = struct.calcsize(COMMON_FMT)

    PRIVATE_FMT = '<LL'
    PRIVATE_SZ = struct.calcsize(PRIVATE_FMT)

    @classmethod
    def get_common(cls):
        version = 1
        endianness = 0x10
        common_header_len = cls.COMMON_SZ
        filter = 0xcccccccc

        return struct.pack(
            cls.COMMON_FMT,
            version,
            endianness,
            common_header_len,
            filter)

    @classmethod
    def get_private(cls, buffer: bytes):
        size = len(buffer)
        filter = 0xcccccccc
        data = struct.pack(
            cls.PRIVATE_FMT,
            size,
            filter)
        # padding is actually over the total, but since common + private = 16
        # this value is equal to the padding over the buffer
        return data, pad8(size) * b'\xFA'

    def read_common(self, data: bytes, offset: int):
        (
            self.version,
            self.endianness,
            self.common_header_len,
            filter
        ) = struct.unpack_from(self.COMMON_FMT, data, offset=offset)

    def read_private(self, data: bytes, offset: int):
        (
            self.size,
            filter,
        ) = struct.unpack_from(self.PRIVATE_FMT, data, offset=offset)
