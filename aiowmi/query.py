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


"""

\x05\x00\x07\x00
\x00\x00\x00\x00
\x00\x00\x00\x00

CID
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00

\xe9\xb7\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf4\xda\x00\x00\x00\x00\x00\x00

\x90\xd5\x00\x00 (referent id)

\x04\x00\x00\x00
\x08\x00\x00\x00
\x04\x00\x00\x00W\x00Q\x00L\x00\x00\x00
\x90\xc2\x00\x00
\x1c\x00\x00\x008\x00\x00\x00\x1c\x00\x00\x00S\x00E\x00L\x00E\x00C\x00T\x00 \x00*\x00 \x00F\x00R\x00O\x00M\x00 \x00W\x00i\x00n\x003\x002\x00_\x00S\x00e\x00r\x00v\x00i\x00c\x00e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00

\x0e\x9a\x00\x00 (referent id 39438)
\x00\x00\x00\x00 (ucount)
\x00\x00\x00\x00 (max)



---------------------------------------------

\x05\x00\x07\x00
\x00\x00\x00\x00
\x00\x00\x00\x00

CID
\xad\x13;N\xa1\xbe\x00i\x87\xebV[\xeb\x04N\x0e

\x00\x00\x00\x00 (extensions)

\n\xc0\x00\x00 (referent id)

\x04\x00\x00\x00
\x08\x00\x00\x00
\x04\x00\x00\x00W\x00Q\x00L\x00\x00\x00
e\x1b\x00\x00
\x1c\x00\x00\x008\x00\x00\x00\x1c\x00\x00\x00S\x00E\x00L\x00E\x00C\x00T\x00 \x00*\x00 \x00F\x00R\x00O\x00M\x00 \x00W\x00i\x00n\x003\x002\x00_\x00S\x00e\x00r\x00v\x00i\x00c\x00e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

\xbct\x00\x00
\x00\x00\x00\x00
\x00\x00\x00\x00


-------------------------------------------------

\x05\x00\x07\x00
\x00\x00\x00\x00
\x00\x00\x00\x00
\x01\x1b\xde=)\xbe\xc8\x14\xaf\xed$\x1e\xa32\r-
\xe9\xb7\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf4\xda\x00\x00\x00\x00\x00\x00

\xa8\xe0\x00\x00

\x04\x00\x00\x00\x08\x00\x00\x00\x04\x00\x00\x00W\x00Q\x00L\x00\x00\x00L\xc5\x00\x00\x1c\x00\x00\x008\x00\x00\x00\x1c\x00\x00\x00S\x00E\x00L\x00E\x00C\x00T\x00 \x00*\x00 \x00F\x00R\x00O\x00M\x00 \x00W\x00i\x00n\x003\x002\x00_\x00S\x00e\x00r\x00v\x00i\x00c\x00e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb6\xec\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

"""

class Query:

    _WQL = WORDSTR('WQL')

    def __init__(self, query: str, language: str = None):
        self.query = query
        self._query = WORDSTR(query)
        self._language = self._WQL if language is None else WORDSTR(language)

    async def start(self, proto: 'Protocol', flags: int = 0):
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