import struct
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING
from ..rpc.request import RpcRequest
from ..rpc.response import RpcResponse
from ..uuid import uuid_to_bin
from .orpcthis import ORPCTHIS


if TYPE_CHECKING:
    from ..protocol import Protocol


class NdrInterface(ABC):

    @abstractmethod
    def get_ipid(self) -> int:
        ...

    async def rem_release(self, proto: 'Protocol'):
        c_public_refs = 1
        c_private_refs = 0

        orpcthis = ORPCTHIS.get_data(flags=0)
        fixed = b'\x01\x00\xce\xce\x01\x00\x00\x00'
        element = uuid_to_bin(self.get_ipid()) + struct.pack(
            '<LL',
            c_public_refs,
            c_private_refs)

        pdu_data = orpcthis + fixed + element

        iremunknown = \
            proto._interface.scm_reply_info_data.ipid_rem_unknown

        request = RpcRequest(op_num=5, uuid_str=iremunknown)
        request.set_pdu_data(pdu_data)

        request_pkg = request.sign_data(proto)

        # rem release shouldn't take long so we can use the default timeout
        rpc_response: RpcResponse = \
            await proto.get_dcom_response(request_pkg, RpcResponse.SIZE)

        message = rpc_response.get_message(proto)
