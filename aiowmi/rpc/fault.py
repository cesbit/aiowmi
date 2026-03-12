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
from ..logger import logger


if TYPE_CHECKING:
    from ..dcom import Dcom


class RpcFault(RpcBaseResp):
    __slots__ = ('status', 'rpc_common')

    FAULT_FMT = '<III'
    FAULT_FMT_SIZE = struct.calcsize(FAULT_FMT)

    def __init__(self, dcom: Dcom, rpc_common: RpcCommon, data: bytes):
        self.rpc_common = rpc_common
        body_data = data[RpcCommon.COMMON_SIZE:]
        self.status = 0x00000721   # RPC_S_SEC_PKG_ERROR (most likely)

        if len(body_data) >= self.FAULT_FMT_SIZE:
            _, _, self.status = struct.unpack(self.FAULT_FMT, body_data[:12])
        elif len(body_data) >= 4:
            alloc_hint = struct.unpack('<I', body_data[:4])[0]
            logger.debug(f"RPC Fault received with alloc_hint: {alloc_hint}")

    def throw(self):
        raise rpc_exception(self.status)
