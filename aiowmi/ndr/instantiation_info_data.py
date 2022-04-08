import struct
from .com_version import COM_VERSION_MAJOR, COM_VERSION_MINOR
from ..tools import pad8, gen_referent_id
from .common import NdrCommon
from ..dcom_const import CLSID_InstantiationInfo


class InstantiationInfoData(NdrCommon):

    CLSID = CLSID_InstantiationInfo

    BUFFER32_FMT = '<LLlLLLLHHL'
    BUFFER32_SZ = struct.calcsize(BUFFER32_FMT)

    BUFFER64_FMT = '<LLlLLQLHHQ'
    BUFFER64_SZ = struct.calcsize(BUFFER64_FMT)

    def __init__(self, class_id: bytes, iid: bytes):
        self.class_id = class_id
        self.iid = [iid]

    def get_data(self) -> bytes:
        class_ctx = 0
        actv_flags = 0
        f_is_surrogate = 0
        c_idd = len(self.iid)
        inst_flag = 0
        referent_id = gen_referent_id()

        referents = b''.join(self.iid)

        this_size = \
            self.COMMON_SZ + \
            self.PRIVATE_SZ + \
            len(self.class_id) + \
            self.BUFFER32_SZ + \
            len(referents)

        # pre-calculate the padding to set this_size to the corrent value
        pad = pad8(this_size)
        this_size += pad

        buffer = self.class_id + struct.pack(
            self.BUFFER32_FMT,
            class_ctx,          # <L
            actv_flags,         # <L
            f_is_surrogate,     # <l (signed)
            c_idd,              # <L
            inst_flag,          # <L
            referent_id,        # <L (32) / <Q (64)
            this_size,          # <L this_size is set to 0 in impacket
            COM_VERSION_MAJOR,  # <H
            COM_VERSION_MINOR,  # <H
            len(self.iid),      # <L (32) / <Q (64) (N referents)
        ) + referents

        private, padding = self.get_private(buffer)

        return self.get_common() + private + buffer + padding
