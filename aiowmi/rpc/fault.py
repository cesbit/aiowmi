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

    __slots__ = ('rpc_common', 'error_code')

    FAULT_FMT = '<L'

    def __init__(self, dcom: Dcom, rpc_common: RpcCommon, data: bytes):
        self.rpc_common = rpc_common

    def throw(self):
        data, n = self.get_pdu_data_list()[0]
        errcode, = struct.unpack_from(self.FAULT_FMT, data)
        raise rpc_exception(errcode)
