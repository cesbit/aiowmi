from __future__ import annotations
from typing import TYPE_CHECKING
import struct
from .common import RpcCommon
from ..tools import pad4
from .result import RpcResult
from .auth_verifier_co import RpcAuthVerifierCo
from .cont_elem import RpcContElem
from ..uuid import bin_to_uuid_ver
from .baseresp import RpcBaseResp

if TYPE_CHECKING:
    from ..dcom import Dcom

# /* common fields */
# u_int16 max_xmit_frag; /* 16:02 max transmit frag size */
# u_int16 max_recv_frag; /* 18:02 max receive frag size */
# u_int32 assoc_group_id; /* 20:04 returned assoc_group_id */
# port_any_t sec_addr; (length u16, char[]) /* 24:yy optional secondary address

# * for process incarnation; local port

# * part of address only */
# /* restore 4-octet alignment */
# u_int8 [size_is(align(4))] pad2;
# /* presentation context result list, including hints */
# p_result_list_t p_result_list; /* variable size */
# typedef struct {
# u_int8 n_results; /* count */

# u_int8 reserved; /* alignment pad, m.b.z. */

# u_int16 reserved2; /* alignment pad, m.b.z. */

# p_result_t [size_is(n_results)] p_results[];

# } p_result_list_t;
# /* optional authentication verifier */
# /* following fields present iff auth_length != 0 */
# auth_verifier_co_t auth_verifier; /* xx:yy */
# } rpcconn_bind_ack_hdr_t


class RpcBindAck(RpcBaseResp):

    __slots__ = ('sec_addr', 'auth', 'rpc_common')

    BIND_ACK_FMT = '<HHLH'
    BIND_ACK_FMT_SIZE = struct.calcsize(BIND_ACK_FMT)

    def __init__(self, dcom: Dcom, rpc_common: RpcCommon, data: bytes):
        offset = RpcCommon.COMMON_SIZE
        (
            max_xmit_frag,
            max_recv_frag,
            assoc_group_id,
            sec_addr_len
        ) = struct.unpack_from(
            self.BIND_ACK_FMT,
            data,
            offset)
        offset += self.BIND_ACK_FMT_SIZE
        self.sec_addr = data[offset:offset+sec_addr_len]
        offset += sec_addr_len
        offset += pad4(offset)

        n_results, _, _ = struct.unpack_from(
            RpcResult.RESULT_LIST_FMT,
            data,
            offset)

        offset += RpcResult.RESULT_LIST_FMT_SIZE

        while n_results:
            offset += 20  # skip transfer syntax
            n_results -= 1

        offset += pad4(offset)

        if rpc_common.auth_length:
            self.auth = RpcAuthVerifierCo(
                data,
                rpc_common.auth_length,
                offset=offset)
        else:
            self.auth = None

        self.rpc_common = rpc_common

        # set max ximit frag
        dcom.set_max_xmit_frag(max_xmit_frag)
