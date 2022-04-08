import struct
from .common import NdrCommon
from ..dcom_const import CLSID_ActivationContextInfo


class ActivationContextInfoData(NdrCommon):

    CLSID = CLSID_ActivationContextInfo

    BUFFER32_FMT = '<llLLLL'

    @classmethod
    def get_data(cls) -> bytes:

        client_ok = 0
        reserved1 = 0
        dw_reserved1 = 0
        dw_reserved2 = 0

        # both contexts are in the format:
        #   ul_cnt_data  <L
        #   ab_data  (bytes)
        # but since we set them to 0, we just pack 0
        p_ifd_client_ctx = 0
        p_ifd_prototype_ctx = 0

        buffer = struct.pack(
            cls.BUFFER32_FMT,
            client_ok,          # <l
            reserved1,          # <l
            dw_reserved1,       # <L
            dw_reserved2,       # <L
            p_ifd_client_ctx,       # <L
            p_ifd_prototype_ctx,    # <L
        )

        private, padding = cls.get_private(buffer)

        return cls.get_common() + private + buffer + padding
