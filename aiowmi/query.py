import struct
from typing import TYPE_CHECKING
from .const import WBEM_INFINITE
from .dtypes.wordstr import WORDSTR
from .ndr.next_response import NextResponse
from .ndr.orpcthis import ORPCTHIS
from .ndr.query_response import QueryResponse
from .ntlm.const import NTLM_AUTH_PKT_INTEGRITY
from .rpc.request import RpcRequest
from .rpc.response import RpcResponse
from .tools import get_null
from .exceptions import wbem_exception


if TYPE_CHECKING:
    from .protocol import Protocol


class Query:

    _WQL = WORDSTR('WQL')

    def __init__(self, query: str, language: str = None):
        self.query = query
        self._query = WORDSTR(query)
        self._language = self._WQL if language is None else WORDSTR(language)

    async def start(self, proto: 'Protocol'):
        """IWbemServices_ExecQuery."""
        pdu_data =\
            ORPCTHIS.get_data(flags=0) +\
            self._language.get_data() +\
            self._query.get_data() +\
            b'\x00\x00\x00\x00' +\
            get_null()

        request = RpcRequest(op_num=20, uuid_str=proto._interface.get_ipid())
        request.set_pdu_data(pdu_data)

        request_pkg = request.sign_data(proto)

        rpc_response: RpcResponse = \
            await proto.get_dcom_response(request_pkg, RpcResponse.SIZE)

        message = rpc_response.get_message(proto)

        interface = QueryResponse(message)
        self._interface = interface
        self._proto = proto

    async def next(self, timeout: int = WBEM_INFINITE) -> NextResponse:
        """IEnumWbemClassObject_Next.

        lTimeout: MUST be the maximum amount of time, in milliseconds, that the
            IEnumWbemClassObject::Next method call allows to pass before it
            times out. If the constant WBEM_INFINITE (0xFFFFFFFF) is specified,
            the call MUST wait until one or more CIM objects are available. If
            the value 0x0 (WBEM_NO_WAIT) is specified, the call MUST return the
            available CIM objects, if any, at the time the call is made, and
            MUST NOT wait for any more objects.
        """
        ucount = 1  # set the ucount fixed to one (1)
        param = struct.pack('<LL', timeout, ucount)
        pdu_data =\
            ORPCTHIS.get_data(flags=0) +\
            param

        request = RpcRequest(op_num=4, uuid_str=self._interface.get_ipid())
        request.set_pdu_data(pdu_data)

        request_pkg = request.sign_data(self._proto)

        rpc_response: RpcResponse = \
            await self._proto.get_dcom_response(request_pkg, RpcResponse.SIZE)

        message = rpc_response.get_message(self._proto)
        next_response = NextResponse(message)

        if next_response.error_code:
            raise wbem_exception(next_response.error_code)

        return next_response
