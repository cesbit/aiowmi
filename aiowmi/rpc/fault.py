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
from ..exceptions import rpc_exception


if TYPE_CHECKING:
    from ..dcom import Dcom


class RpcFault(RpcBaseResp):
    __slots__ = ('status', 'rpc_common')

    FAULT_FMT = '<IIII'
    FAULT_FMT_SIZE = struct.calcsize(FAULT_FMT)

    ERROR_MAP = {
        0x00000005: "RPC_S_ACCESS_DENIED",
        0x000006D9: "RPC_S_EPT_MAP_NO_MORE_ENTRIES",
        0x00000721: "RPC_S_PROTOCOL_ERROR",
        0x000006A6: "RPC_S_INVALID_BINDING",
        0x1C010001: "RPC_S_PROTSEQ_NOT_SUPPORTED",
        0x1C00001B: "RPC_JT_UNKNOWN_IF (Unkown Interface on Server)"
    }

    def __init__(self, dcom: Dcom, rpc_common: RpcCommon, data: bytes):
        self.rpc_common = rpc_common

        offset = RpcCommon.COMMON_SIZE
        alloc_hint, unknown, self.status, reserved = \
            struct.unpack_from(self.FAULT_FMT, data, offset)
        print(self.status)

    def get_error_message(self) -> str:
        friendly_msg = self.ERROR_MAP.get(self.status, "Unknown RPC Error")
        return f"MSRPC Fault: {friendly_msg} (0x{self.status:08x})"

    def throw(self):
        raise rpc_exception(self.status)
