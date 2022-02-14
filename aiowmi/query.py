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
from .tools import get_null, gen_referent_id
from .exceptions import wbem_exception


if TYPE_CHECKING:
    from .protocol import Protocol
    from .connection import Connection


class Query:

    _WQL = WORDSTR('WQL')

    def __init__(
            self,
            query: str,
            namespace: str = 'root/cimv2',
            language: str = None):
        if not namespace.startswith('//'):
            namespace = '//./' + namespace
        self.query = query
        self.namespace = namespace
        self._query = WORDSTR(query)
        self._language = self._WQL if language is None else WORDSTR(language)

    async def start(
            self,
            conn: 'Connection',
            proto: 'Protocol',
            flags: int = 0):
        """IWbemServices_ExecQuery.
        3.1.4.3.18 IWbemServices::ExecQuery (Opnum 20) [MS-WMI]

        Optional flags: (import from aiowmi.const)

        WBEM_FLAG_USE_AMENDED_QUALIFIERS (0x00020000)
            If this bit is not set, the server SHOULD not return CIM
            localizable information.
            If this bit is set, the server SHOULD return CIM localizable
            information for the CIM object, as specified in section 2.2.6.
        WBEM_FLAG_RETURN_IMMEDIATELY (0x00000010)
            If this bit is not set, the server MUST make the method
            call synchronously. If this bit is set, the server MUST make the
            method call semisynchronously.
        WBEM_FLAG_DIRECT_READ (0x00000200)
            If this bit is not set, the server MUST consider the entire
            class hierarchy when it returns the result.
            If this bit is set, the server MUST disregard any derived
            class when it searches the result.
        WBEM_FLAG_PROTOTYPE (0x00000002)
            If this bit is not set, the server MUST run the query.
            If this bit is set, the server MUST only return the class
        WBEM_FLAG_FORWARD_ONLY (0x00000020)
            If this bit is not set, the server MUST return an
            enumerator that has reset capability.
            If this bit is set, the server MUST return an enumerator
            without reset capability, as specified in section
        """
        if conn._namespace != self.namespace:
            await conn.login_ntlm(proto, namespace=self.namespace)

        flags = struct.pack('<L', flags)
        pdu_data =\
            ORPCTHIS.get_data(flags=0) +\
            self._language.get_data() +\
            self._query.get_data() +\
            flags +\
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

    async def _start_async(self, proto: 'Protocol', flags: int = 0):
        """IWbemServices_ExecQuery.

        3.1.4.3.19 IWbemServices::ExecQueryAsync (Opnum 21) [MS-WMI]

        Optional flags: (import from aiowmi.const)

        WBEM_FLAG_USE_AMENDED_QUALIFIERS (0x00020000)
            If this bit is not set, the server SHOULD not return CIM
            localizable information.
            If this bit is set, the server SHOULD return CIM localizable
            information for the CIM object, as specified in section 2.2.6.
        WBEM_FLAG_SEND_STATUS (0x00000080)
            If this bit is not set the server MUST make one final
            IWbemObjectSink::SetStatus call on the interface pointer that
            is provided in the pResponseHandler parameter.
        WBEM_FLAG_PROTOTYPE (0x00000002)
            If this bit is not set, the server MUST run the query.
            If this bit is set, the server MUST only return the class
        WBEM_FLAG_DIRECT_READ (0x00000200)
            If this bit is not set, the server MUST consider the entire
            class hierarchy when it returns the result.
            If this bit is set, the server MUST disregard any derived
            class when it searches the result.
        """
        assert 0, 'not working yet...'

        flags = struct.pack('<L', flags)

        pdu_data =\
            ORPCTHIS.get_data(flags=0) +\
            self._language.get_data() +\
            self._query.get_data() +\
            flags +\
            get_null() +\
            get_null()

        request = RpcRequest(op_num=21, uuid_str=proto._interface.get_ipid())
        request.set_pdu_data(pdu_data)

        request_pkg = request.sign_data(proto)

        rpc_response: RpcResponse = \
            await proto.get_dcom_response(request_pkg, RpcResponse.SIZE)

        message = rpc_response.get_message(proto)

        interface = QueryResponse(message)
        self._interface = interface
        self._proto = proto
