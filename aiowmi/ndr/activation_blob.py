import struct
from .ndr_info_data import NdrInfoData
from ..tools import gen_referent_id
from .common import NdrCommon
from ..uuid import bin_to_str, CLSID_SZ


class ActivationBlob(NdrCommon):

    CLSID_NULL = b'\x00' * CLSID_SZ

    START_FMT = '<LL'
    START_SZ = struct.calcsize(START_FMT)

    BUF_FMT = '<LLLLL'
    BUF_SZ = struct.calcsize(BUF_FMT)

    CLSIDS32_FMT = '<LLLL'
    CLSIDS32_SZ = struct.calcsize(CLSIDS32_FMT)

    CLSIDS64_FMT = '<QQLL'  # not sure if the second is a referentId
    CLSIDS64_SZ = struct.calcsize(CLSIDS64_FMT)

    def __init__(self, dest_ctx: int = 2):
        self.dest_ctx = dest_ctx
        self.pclsid = []
        self.psizes = []
        self.properties = []

    @classmethod
    def from_data(cls, data: bytes):
        offset = 0
        self = cls()
        (
            total_size,
            dw_reserved,
        ) = struct.unpack_from(cls.START_FMT, data, offset=offset)
        offset += cls.START_SZ

        self.read_common(data, offset=offset)
        offset += self.COMMON_SZ

        self.read_private(data, offset=offset)
        offset += self.PRIVATE_SZ

        (
            self.total_size,
            self.header_size,
            dw_reserved,
            self.dest_ctx,
            c_ifs,
        ) = struct.unpack_from(cls.BUF_FMT, data, offset=offset)
        offset += cls.BUF_SZ

        self.clsid = bin_to_str(data, offset=offset)
        offset += CLSID_SZ

        (
            self.referent_id1,
            self.referent_id2,
            dw_reserved,
            c_clsids,
        ) = struct.unpack_from(cls.CLSIDS32_FMT, data, offset=offset)
        offset += cls.CLSIDS32_SZ

        for _ in range(c_clsids):
            clsid = bin_to_str(data, offset=offset)
            offset += CLSID_SZ
            self.pclsid.append(clsid)

        n_psizes, = struct.unpack_from('<L', data, offset=offset)
        offset += 4  # size(<L)

        for _ in range(n_psizes):
            size, = struct.unpack_from('<L', data, offset=offset)
            offset += 4  # size(<L)
            self.psizes.append(size)

        for size in self.psizes:
            self.properties.append(data[offset: offset+size])
            offset += size

        return self

    def add_info_data(self, info_data: NdrInfoData):
        data = info_data.get_data()
        self.pclsid.append(info_data.CLSID)
        self.psizes.append(len(data))
        self.properties.append(data)

    def get_data(self):
        dw_reserved = 0
        c_psizes = c_clsids = c_ifs = len(self.pclsid)

        referent_id1 = gen_referent_id()
        referent_id2 = gen_referent_id()

        psizes = \
            b''.join([struct.pack('<L', x) for x in [c_psizes] + self.psizes])
        clsids = b''.join(self.pclsid)
        properties = b''.join(self.properties)

        # TODO: should we include padding to the header size?
        # probably the total size should include padding before the properties?
        header_size = \
            self.COMMON_SZ + \
            self.PRIVATE_SZ + \
            self.BUF_SZ + \
            CLSID_SZ + \
            self.CLSIDS32_SZ + \
            len(clsids) + \
            len(psizes)
        total_size = header_size + len(properties)

        buffer = struct.pack(
            self.BUF_FMT,
            total_size,
            header_size,
            dw_reserved,
            self.dest_ctx,
            c_ifs,
        ) + self.CLSID_NULL + struct.pack(
            self.CLSIDS32_FMT,
            referent_id1,
            referent_id2,
            dw_reserved,
            c_clsids,
        ) + clsids + psizes

        private, padding = self.get_private(buffer)

        data = struct.pack(
            self.START_FMT,
            total_size,
            dw_reserved
        ) + self.get_common() + private + buffer + padding + properties

        return data
