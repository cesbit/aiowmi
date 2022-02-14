from .dcom_const import IID_IRemoteSCMActivator
from .dcom_const import NDR_TransferSyntaxIdentifier
from .exceptions import DcomException
from .ntlm.auth_authenticate import NTLMAuthAuthenticate
from .ntlm.auth_negotiate import NTLMAuthNegotiate
from .rpc.auth_verifier_co import RpcAuthVerifierCo
from .rpc.bind import RpcBind
from .rpc.bind_ack import RpcBindAck
from .rpc.common import RpcCommon
from .rpc.const import MSRPC_AUTH3
from .rpc.const import MSRPC_BINDACK
from .rpc.const import MSRPC_FAULT
from .rpc.const import MSRPC_RESPONSE
from .rpc.const import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from .rpc.const import RPC_C_AUTHN_WINNT
from .rpc.cont_elem import RpcContElem
from .rpc.fault import RpcFault
from .rpc.response import RpcResponse
from .tools import pad4


class Dcom:
    def __init__(self):
        self._max_xmit_frag = None  # set be negotiation (MSRPC_BINDACK)
        self._call_id = 1
        self._seq_num = 0

    def set_max_xmit_frag(self, max_xmit_frag: int):
        self._max_xmit_frag = max_xmit_frag

    def set_call_id(self, rpc_common: RpcCommon):
        rpc_common.call_id = self._call_id
        self._call_id += 1

    def get_seq_num(self):
        seq_num = self._seq_num
        self._seq_num += 1
        return seq_num

    def get_negotiate_ntlm_pkg(
            self,
            iid: bytes,
            ntlm_auth_negotiate: NTLMAuthNegotiate,
            auth_level: int):
        rpc_bind = RpcBind()

        rpc_cont_elem = RpcContElem(iid)
        rpc_cont_elem.add_transfer_syntax(NDR_TransferSyntaxIdentifier)
        rpc_bind.add_cont_elem(rpc_cont_elem)

        auth_pad_length = pad4(rpc_bind.freeze_context())

        auth_verifier, auth_length = RpcAuthVerifierCo.make(
            RPC_C_AUTHN_WINNT,
            auth_level,
            auth_pad_length,
            4242,  # context id
            ntlm_auth_negotiate.get_data())

        rpc_bind.set_auth_verifier(auth_verifier, auth_length)
        self.set_call_id(rpc_bind)

        data = rpc_bind.get_data()
        return data

    @staticmethod
    def get_authenticate_ntlm_pkg(
            ntlm_auth_authenticate: NTLMAuthAuthenticate,
            auth_level: int) -> bytes:

        rpc_common = RpcCommon()
        rpc_common.init(MSRPC_AUTH3)

        ntlm_auth_data = ntlm_auth_authenticate.get_data()

        auth_verifier, auth_length = RpcAuthVerifierCo.make(
            RPC_C_AUTHN_WINNT,
            auth_level,
            0,
            4242,  # context id
            ntlm_auth_data)
        rpc_common.set_pdu_data(b'    ')
        rpc_common.set_auth_verifier(auth_verifier, auth_length)

        data = rpc_common.get_data()
        return data

    _DCOM_RPC_MAP = {
        MSRPC_BINDACK: RpcBindAck,
        MSRPC_RESPONSE: RpcResponse,
        MSRPC_FAULT: RpcFault,
    }
