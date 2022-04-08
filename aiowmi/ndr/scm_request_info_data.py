import struct
import random
from .common import NdrCommon
from ..tools import gen_referent_id
from ..dcom_const import CLSID_ScmRequestInfo


class ScmRequestInfoData(NdrCommon):

    CLSID = CLSID_ScmRequestInfo

    BUFFER32_FMT = '<lLLH'
    BUFFER64_FMT = '<lQLH'

    REFERENT32_FMT = '<LL'
    REFERENT64_FMT = '<LQ'

    @classmethod
    def get_data(cls) -> bytes:
        p_requested_prot_seqs = [7]

        dw_reserved = 0
        referent_id = gen_referent_id()
        client_imp_level = 0
        c_requested_prot_seqs = 1

        referents = b''.join([
            struct.pack('<H', x)
            for x in p_requested_prot_seqs])

        padding = b'\xaa\xaa'  # can be fiex as this is aways the same

        buffer = struct.pack(
            cls.BUFFER32_FMT,
            dw_reserved,            # <l
            referent_id,            # <L (32) / <Q (64)
            client_imp_level,       # <L
            c_requested_prot_seqs,  # <H
        ) + padding

        referent_id = gen_referent_id()

        buffer += struct.pack(
            cls.REFERENT32_FMT,
            referent_id,
            len(p_requested_prot_seqs),
        ) + referents

        private, padding = cls.get_private(buffer)

        return cls.get_common() + private + buffer + padding
