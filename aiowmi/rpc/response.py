from __future__ import annotations
from typing import TYPE_CHECKING, Callable
import struct
from .common import RpcCommon
from ..tools import pad4
from .result import RpcResult
from .auth_verifier_co import RpcAuthVerifierCo
from .cont_elem import RpcContElem
from ..uuid import bin_to_uuid_ver
from .baseresp import RpcBaseResp
from .const import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from .const import RPC_C_AUTHN_WINNT
from ..exceptions import wbem_exception


if TYPE_CHECKING:
    from ..dcom import Dcom
    from ..protocol import Protocol

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


class RpcResponse(RpcBaseResp):

    __slots__ = ('rpc_common', 'ctx_id', 'cancel_count', 'padding')

    RESPONSE_FMT = '<LHBB'
    RESPONSE_SIZE = struct.calcsize(RESPONSE_FMT)
    SIZE = RpcCommon.COMMON_SIZE + RESPONSE_SIZE

    ERR_FMT = '<L'

    def __init__(self, dcom: Dcom, rpc_common: RpcCommon, data: bytes):
        offset = RpcCommon.COMMON_SIZE
        (
            alloc_hint,
            self.ctx_id,
            self.cancel_count,
            self.padding
        ) = struct.unpack_from(
            self.RESPONSE_FMT,
            data,
            offset)

        self.rpc_common = rpc_common

    def get_message(self, proto: Protocol):
        messages = []
        for (resp, n) in self.get_pdu_data_list():
            auth_n = self.rpc_common.auth_length
            if auth_n:
                offset = n - (auth_n + RpcAuthVerifierCo.SIZE)
                auth = RpcAuthVerifierCo(resp, auth_n, offset)
                resp = resp[:offset]

                if auth.auth_level == RPC_C_AUTHN_LEVEL_PKT_PRIVACY:
                    if auth.auth_type == RPC_C_AUTHN_WINNT:
                        message, signature = proto._server_seal(
                            flags=proto._flags,
                            seq_num=proto._dcom._seq_num,
                            message_to_sign=resp,
                            message_to_encrypt=resp)
                else:
                    # Check signing?
                    message = resp

                if auth.auth_pad_length:
                    message = message[:-auth.auth_pad_length]
            else:
                # no authentication ??
                message = resp
            messages.append(message)

        if not message.endswith(b'\x00\x00\x00\x00'):
            # First, rpc status codes should also have an rpc fault package
            # and are already handled.
            # Second, WBEM_S "errors" are not relevant and can be distinguished
            # with the 0x80000000 bit, although, we do raise them
            errcode, = struct.unpack('<L', message[-4:])
            raise wbem_exception(errcode)

        return b''.join(messages)
