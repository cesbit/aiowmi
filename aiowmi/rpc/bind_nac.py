from __future__ import annotations
import struct
from typing import TYPE_CHECKING
from .common import RpcCommon
from ..tools import pad4
from .result import RpcResult
from .auth_verifier_co import RpcAuthVerifierCo
from .cont_elem import RpcContElem
from ..uuid import bin_to_uuid_ver
from .baseresp import RpcBaseResp
from ..exceptions import BindNak


if TYPE_CHECKING:
    from ..dcom import Dcom


class RpcBindNak(RpcBaseResp):

    def __init__(self, dcom: Dcom, rpc_common: RpcCommon, data: bytes):
        if len(data) < 24:
            raise BindNak("Packet too short")

        header = struct.unpack('<BBBBIHHI', data[:16])
        pdu_type = header[2]
        call_id = header[7]

        if pdu_type != 13:
            raise BindNak(
                f"Error: PDU type is {pdu_type}, expecting 13 (Bind_nak).")

        provider_reason_code = struct.unpack('<H', data[16:18])[0]
        status_code = struct.unpack('<H', data[18:20])[0]

        provider_reasons = {
            0: "REASON_NOT_SPECIFIED (General error)",
            1: "TEMPORARY_CONGESTION (Server to0 busy)",
            2: "LOCAL_LIMIT_EXCEEDED (Too many sessions)",
            3: "PROTOCOL_VERSION_NOT_SUPPORTED (Protocol version mismatch)",
            4: "AUTHENTICATION_TYPE_NOT_SUPPORTED (Authentication denied)",
            5: "INVALID_AUTH_INSTANCE (Invalid authentication data)"
        }

        windows_errors = {
            0x0501: "RPC_S_PROTSEQ_NOT_SUPPORTED (Security flags denied)",
            0x0005: "ERROR_ACCESS_DENIED (Access denied)",
            0x06d3:
            "RPC_S_AUTHN_LEVEL_LOW (Auth level too low, PKT_PRIVACY required)",
            0x1c01000b:
            "RPC_S_WRONG_KIND_OF_AUTH (Wrong authentication method)"
        }

        reason_text = provider_reasons.get(provider_reason_code,
                                           f"Unknown ({provider_reason_code})")
        error_text = windows_errors.get(status_code,
                                        "Unknown Windows error")

        output = [
            "--- MSRPC BIND_NAK ---",
            f"Call ID         : {call_id}",
            f"Provider Reason : {reason_text}",
            f"Windows Status  : 0x{status_code:04x} -> {error_text}",
            "------------------------------"
        ]

        raise BindNak("\n".join(output))
