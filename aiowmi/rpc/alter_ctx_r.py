from __future__ import annotations
from typing import TYPE_CHECKING
import struct
from .common import RpcCommon
from ..tools import pad4
from .result import RpcResult
from .auth_verifier_co import RpcAuthVerifierCo
from .baseresp import RpcBaseResp

if TYPE_CHECKING:
    from ..dcom import Dcom

# /* Alter Context Response fields */
# u_int16 max_xmit_frag;    /* 16:02 max transmit frag size */
# u_int16 max_recv_frag;    /* 18:02 max receive frag size */
# u_int32 assoc_group_id;   /* 20:04 returned assoc_group_id */
# /* NOTE: NO secondary address field in AlterCtxR! */
# u_int8 pad1[4];           /* restore 4-octet alignment */
# p_result_list_t p_result_list;


class RpcAlterCtxR(RpcBaseResp):

    __slots__ = (
        'max_xmit_frag',
        'max_recv_frag',
        'assoc_group_id',
        'auth',
        'rpc_common')

    ALTER_CTX_R_FMT = '<HHL'
    ALTER_CTX_R_FMT_SIZE = struct.calcsize(ALTER_CTX_R_FMT)

    def __init__(self, dcom: Dcom, rpc_common: RpcCommon, data: bytes):
        offset = RpcCommon.COMMON_SIZE
        (
            self.max_xmit_frag,
            self.max_recv_frag,
            self.assoc_group_id
        ) = struct.unpack_from(self.ALTER_CTX_R_FMT, data, offset)

        offset += self.ALTER_CTX_R_FMT_SIZE
        offset += pad4(offset)

        n_results, reserved, reserved2 = struct.unpack_from(
            RpcResult.RESULT_LIST_FMT,
            data,
            offset
        )
        offset += RpcResult.RESULT_LIST_FMT_SIZE

        for _ in range(n_results):
            offset += 24

        offset += pad4(offset)

        if rpc_common.auth_length:
            # negTokenResp
            self.auth = RpcAuthVerifierCo(
                data,
                rpc_common.auth_length,
                offset=offset)
        else:
            self.auth = None

        self.rpc_common = rpc_common
        dcom.set_max_xmit_frag(self.max_xmit_frag)
