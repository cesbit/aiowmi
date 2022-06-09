import logging
import struct
from typing import TYPE_CHECKING
from .const import WBEM_FLAG_FORWARD_ONLY
from .const import WBEM_FLAG_RETURN_IMMEDIATELY
from .const import WBEM_INFINITE
from .dcom_const import IID_IRemUnknown_str
from .dcom_const import IID_IWbemFetchSmartEnum_bin
from .dtypes.wordstr import WORDSTR
from .exceptions import wbem_exception
from .ndr.get_smart_enum_response import GetSmartEnumResponse
from .ndr.next_response import NextResponse
from .ndr.orpcthis import ORPCTHIS
from .ndr.query_response import QueryResponse
from .ndr.smart_response import SmartResponse
from .ndr.next_big_response import NextBigResponse
from .ndr.rem_query_interface_response import RemQueryInterfaceResponse
from .ntlm.const import NTLM_AUTH_PKT_INTEGRITY
from .rpc.request import RpcRequest
from .rpc.response import RpcResponse
from .tools import get_null, gen_referent_id
from .uuid import uuid_to_bin


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
            flags: int = (
                WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY)):
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
            ORPCTHIS.get_data() +\
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

        # this works, but do we need a rem release or not?
        # ...we did not ask for one
        # await proto._interface.rem_release(proto)

        interface = QueryResponse(message)
        self._interface = interface
        self._proto = proto
        self.next = self._next_slow

    async def optimize(self):
        """RemQueryInterface."""
        ipid = uuid_to_bin(self._interface.get_ipid())

        c_refs, c_iids = 1, 1

        pdu_data =\
            ORPCTHIS.get_data(flags=0) +\
            ipid +\
            struct.pack('<LH', c_refs, c_iids) +\
            b'\xce\xce' +\
            struct.pack('<L', c_iids) +\
            IID_IWbemFetchSmartEnum_bin

        iremunknown = \
            self._proto._interface.scm_reply_info_data.ipid_rem_unknown

        request = RpcRequest(op_num=3, uuid_str=iremunknown)
        request.set_pdu_data(pdu_data)

        request_pkg = request.sign_data(self._proto)

        rpc_response: RpcResponse = \
            await self._proto.get_dcom_response(request_pkg, RpcResponse.SIZE)

        message = rpc_response.get_message(self._proto)

        interface = RemQueryInterfaceResponse(message)

        pdu_data = ORPCTHIS.get_data(flags=0) + ipid
        request = RpcRequest(op_num=3, uuid_str=interface.get_ipid())
        request.set_pdu_data(pdu_data)

        request_pkg = request.sign_data(self._proto)

        rpc_response: RpcResponse = \
            await self._proto.get_dcom_response(request_pkg, RpcResponse.SIZE)

        message = rpc_response.get_message(self._proto)

        # we asked for one public inferface, so we need to release this one
        await interface.rem_release(self._proto)

        interface = GetSmartEnumResponse(message)

        self._class_parts = {}
        self._interface = interface
        self.next = self._next_smart

    async def done(self):
        # this works, but do we need a rem release or not?
        try:
            await self._interface.rem_release(self._proto)
        except Exception as e:
            logging.warning(e)
        self._interface = None
        self._proto = None
        self.next = None
        if hasattr(self, '_class_parts'):
            self._class_parts.clear()

    async def _next_smart(self, timeout: int = WBEM_INFINITE) -> NextResponse:
        """3.1.4.7.1 IWbemWCOSmartEnum::Next (Opnum 3)"""
        ucount = 1  # set the ucount fixed to one (1)
        param = struct.pack('<LL', timeout, ucount)
        pdu_data =\
            ORPCTHIS.get_data(flags=0) +\
            self._interface.proxy_guid +\
            param

        request = RpcRequest(op_num=3, uuid_str=self._interface.get_ipid())
        request.set_pdu_data(pdu_data)

        request_pkg = request.sign_data(self._proto)

        rpc_response: RpcResponse = \
            await self._proto.get_dcom_response(request_pkg, RpcResponse.SIZE)

        message = rpc_response.get_message(self._proto)
        return SmartResponse(message, self._class_parts)

    async def _next_slow(self, timeout: int = WBEM_INFINITE) -> NextResponse:
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
        return NextBigResponse(message)
