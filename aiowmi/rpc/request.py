"""
To Enctypt:
b'\x05\x00\x07\x00\x01\x00\x00....


To Sign:
Mayor, Minor, Ptype, Flags
\x05
\x00
\x00
\x03

Packed drep
\x10\x00\x00\x00

Frag len (512)
\x00\x02

Auth len
\x10\x00

CallId
\x02\x00\x00\x00

Alloc hint  (464, encrypted pduData)
\xd0\x01\x00\x00

ContextId
\x00\x00

Op num
\x04\x00

PduData
\x05\x00\x07\x00...

sec trailer
\n\x06\x00\x00\x7f5\x01\x00'
"""

import struct
from typing import TYPE_CHECKING, Optional
from .common import RpcCommon
from .cont_elem import RpcContElem
from .const import MSRPC_REQUEST, PFC_OBJECT_UUID
from .const import RPC_C_AUTHN_LEVEL_PKT_INTEGRITY
from .const import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from .const import RPC_C_AUTHN_WINNT, RPC_C_AUTHN_GSS_NEGOTIATE
from ..rpc.auth_verifier_co import RpcAuthVerifierCo
from ..tools import pad4
from ..uuid import uuid_to_bin


if TYPE_CHECKING:
    from ..protocol import Protocol


class RpcRequest(RpcCommon):

    AUTH_SZ = 16
    AUTH_VALUE = b' '*AUTH_SZ

    def __init__(self, op_num: int, uuid_str: Optional[str] = None):
        super().init(MSRPC_REQUEST)
        if uuid_str is not None:
            self.pfc_flags |= PFC_OBJECT_UUID
        self.op_num = op_num
        self.uuid_str = uuid_str

    def seal_data(self, proto: 'Protocol', ctx_id: int = 0) -> bytes:
        auth_pad_length = pad4(self._pdu_data_len)
        message_to_encrypt = self._pdu_data
        alloc_hint = len(message_to_encrypt)
        pdu_data = struct.pack(
            '<LHH',
            alloc_hint,
            ctx_id,
            self.op_num,
        )
        if self.pfc_flags & PFC_OBJECT_UUID:
            assert self.uuid_str is not None
            uuid = uuid_to_bin(self.uuid_str)
            pdu_data += uuid

        self.set_pdu_data(pdu_data + message_to_encrypt)

        auth_verifier, auth_length = RpcAuthVerifierCo.make(
            proto._auth_type,
            proto._auth_level,
            auth_pad_length,
            proto._context_id,
            self.AUTH_VALUE)

        proto._dcom.set_call_id(self)
        self.set_auth_verifier(auth_verifier, auth_length)

        # need the auth verifier, but not the auth data
        message_to_sign = self.get_data()[:-self.AUTH_SZ]

        sealed_message, message_signature = proto._client_seal(
            flags=proto._flags,
            seq_num=proto._dcom.get_seq_num(),
            message_to_sign=message_to_sign,
            message_to_encrypt=message_to_encrypt)

        self.set_pdu_data(pdu_data + sealed_message)
        self.set_auth_data(message_signature)

        return self.get_data()

    def sign_data(self, proto: 'Protocol', ctx_id: int = 0) -> bytes:
        auth_pad_length = pad4(self._pdu_data_len)
        alloc_hint = len(self._pdu_data)
        pdu_data = struct.pack(
            '<LHH',
            alloc_hint,
            ctx_id,
            self.op_num,
        )
        if self.pfc_flags & PFC_OBJECT_UUID:
            uuid = uuid_to_bin(self.uuid_str)
            pdu_data += uuid

        message_to_sign = self._pdu_data
        self.set_pdu_data(pdu_data + self._pdu_data)

        auth_verifier, auth_length = RpcAuthVerifierCo.make(
            proto._auth_type,
            proto._auth_level,
            auth_pad_length,
            proto._context_id,  # context id
            self.AUTH_VALUE)

        proto._dcom.set_call_id(self)
        self.set_auth_verifier(auth_verifier, auth_length)

        seq_num = proto._dcom.get_seq_num()

        if proto._auth_level == RPC_C_AUTHN_LEVEL_PKT_INTEGRITY:
            if proto._auth_type == RPC_C_AUTHN_WINNT:
                # need the auth verifier, but not the auth data
                message_to_sign = self.get_data()[:-self.AUTH_SZ]
                message_signature = proto._client_sign(
                    flags=proto._flags,
                    seq_num=seq_num,
                    message_to_sign=message_to_sign)
            else:
                raise Exception(
                    f'Unsupported auth_type ({proto._auth_type}) '
                    f'for auth_level ({proto._auth_level})')
        elif proto._auth_level == RPC_C_AUTHN_LEVEL_PKT_PRIVACY:
            if proto._auth_type == RPC_C_AUTHN_GSS_NEGOTIATE:
                sealed_message, message_signature = proto._client_sign(
                    flags=proto._flags,
                    seq_num=seq_num,
                    message_to_sign=message_to_sign)
                self.set_pdu_data(pdu_data + sealed_message)
            else:
                raise Exception(
                    f'Unsupported auth_type ({proto._auth_type}) '
                    f'for auth_level ({proto._auth_level})')
        else:
            raise Exception(f'Unsupported auth_level: {proto._auth_level}')

        self.set_auth_data(message_signature)
        return self.get_data()
