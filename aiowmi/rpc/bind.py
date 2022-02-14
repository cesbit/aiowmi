import struct
from .common import RpcCommon
from .cont_elem import RpcContElem
from .const import MSRPC_BIND


# 12.6.4.5 The bind_nak PDU
# The IDL declaration of the bind_nak PDU is as follows:
# typedef struct {
#   /* include common fields */
#   u_int16 max_xmit_frag; /* 16:02 max transmit frag size, bytes */
#   u_int16 max_recv_frag; /* 18:02 max receive frag size, bytes */
#   u_int32 assoc_group_id; /* 20:04 incarnation of client-server
#   struct {
#     u_int8 n_context_elem; /* number of items */
#     u_int8 reserved; /* alignment pad, m.b.z. */
#     u_short reserved2; /* alignment pad, m.b.z. */
#     p_cont_elem_t [size_is(n_cont_elem)] p_cont_elem[];
#   }
#   /* optional authentication verifier */
#   /* following fields present iff auth_length != 0 */
#   auth_verifier_co_t auth_verifier;
# }


class RpcBind(RpcCommon):
    FMT = '<HHLBBH'

    def __init__(self):
        super().init(MSRPC_BIND)

        self._max_xmit_frag = 0x10b8
        self._max_recv_frag = 0x10b8
        self._assoc_group_id = 0
        self._n_context_elem = 0
        self._reserved = 0
        self._reserved2 = 0
        self._p_cont_elem = []

    def add_cont_elem(self, cont_elem: RpcContElem) -> None:
        """Add Context Element."""
        cont_elem.p_cont_id = self._n_context_elem
        self._p_cont_elem.append(cont_elem)
        self._n_context_elem += 1

    def freeze_context(self) -> int:
        """Freeze the context and return the context length."""
        pdu_data = struct.pack(
            self.FMT,
            self._max_xmit_frag,            # 1. <H
            self._max_recv_frag,            # 2. <H
            self._assoc_group_id,           # 3. <L
            self._n_context_elem,           # 3. B
            self._reserved,                 # 4. B
            self._reserved2,                # 5. <H
        ) + b''.join(cont_elem.get_data() for cont_elem in self._p_cont_elem)
        return self.set_pdu_data(pdu_data)
