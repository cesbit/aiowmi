from __future__ import annotations
from typing import TYPE_CHECKING
from .common import RpcCommon
from ..tools import pad4
from .result import RpcResult
from .auth_verifier_co import RpcAuthVerifierCo
from .cont_elem import RpcContElem
from ..uuid import bin_to_uuid_ver
from .baseresp import RpcBaseResp

if TYPE_CHECKING:
    from ..dcom import Dcom


class RpcBindNak(RpcBaseResp):

    def __init__(self, dcom: Dcom, rpc_common: RpcCommon, data: bytes):
        reason = data[20:22] if len(data) >= 22 else "Unknown"
        print(data)
        raise Exception(reason)  # Exception: b'\x00\x00'
