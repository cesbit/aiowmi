import struct
import asyncio
from typing import OrderedDict
from .const import WBEM_INFINITE
from .dcom_const import IID_IWbemFetchSmartEnum_bin
from .exceptions import WbemFalse, ServerNotOptimized
from .ndr.get_smart_enum_response import GetSmartEnumResponse
from .ndr.interface import NdrInterface
from .ndr.next_big_response import NextBigResponse
from .ndr.next_response import NextResponse
from .ndr.orpcthis import ORPCTHIS
from .ndr.property_info import PropertyInfo
from .ndr.query_response import QueryResponse
from .ndr.rem_query_interface_response import RemQueryInterfaceResponse
from .ndr.smart_response import SmartResponse
from .protocol import Protocol
from .rpc.request import RpcRequest
from .rpc.response import RpcResponse
from .tools import get_null
from .uuid import uuid_to_bin


class QContext:
    def __init__(
            self,
            query,
            conn,
            flags,
            proto,
            timeout,
            skip_optimize):
        self._conn = conn
        self._flags = flags
        self._class_parts = {}
        self._proto = proto
        self._timeout = timeout
        self._skip_optimize = skip_optimize
        self._query = query
        self._interface = None
        self.next = self._next_slow

    def results(
            self,
            ignore_defaults: bool = False,
            ignore_missing: bool = False,
            load_qualifiers: bool = False) -> OrderedDict[str, PropertyInfo]:
        self._ignore_defaults = ignore_defaults
        self._ignore_missing = ignore_missing
        self._load_qualifiers = load_qualifiers
        return self

    async def __aenter__(self):
        await self.start()
        return self

    async def start(self):
        if self._conn._namespace != self._query.namespace:
            await self._conn.login_ntlm(
                self._proto, namespace=self._query.namespace)

        flags = struct.pack('<L', self._flags)
        pdu_data =\
            ORPCTHIS.get_data() +\
            self._query._language.get_data() +\
            self._query._query.get_data() +\
            flags +\
            get_null()

        # Both conn and quert are no longer required
        self._conn = None
        self._query = None

        request = RpcRequest(
            op_num=20, uuid_str=self._proto._interface.get_ipid())
        request.set_pdu_data(pdu_data)

        request_pkg = request.sign_data(self._proto)

        rpc_response: RpcResponse = \
            await self._proto.get_dcom_response(
                request_pkg,
                size=RpcResponse.SIZE,
                timeout=self._timeout)

        message = rpc_response.get_message(self._proto)

        self._interface = QueryResponse(message)

        if not self._skip_optimize:
            try:
                await self.optimize()
            except ServerNotOptimized:
                pass

    async def __aexit__(self, exc_type, exc, tb):
        await self.release()

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            next_response = await self.next()
        except WbemFalse:
            raise StopAsyncIteration
        return next_response.get_properties(
            self._ignore_defaults,
            self._ignore_missing,
            self._load_qualifiers)

    @property
    def is_optimized(self) -> bool:
        return self.next is self._next_smart

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

        # optimizing shouldn't take long so we can use the default timeout
        rpc_response: RpcResponse = \
            await self._proto.get_dcom_response(request_pkg, RpcResponse.SIZE)

        message = rpc_response.get_message(self._proto)

        interface = RemQueryInterfaceResponse(message)

        pdu_data = ORPCTHIS.get_data(flags=0) + ipid
        request = RpcRequest(op_num=3, uuid_str=interface.get_ipid())
        request.set_pdu_data(pdu_data)

        request_pkg = request.sign_data(self._proto)

        # optimizing shouldn't take long so we can use the default timeout
        rpc_response: RpcResponse = \
            await self._proto.get_dcom_response(request_pkg, RpcResponse.SIZE)

        message = rpc_response.get_message(self._proto)

        # we asked for one public inferface, so we need to release this one
        await interface.rem_release(self._proto)

        interface = GetSmartEnumResponse(message)

        self._class_parts = {}
        self._interface = interface
        self.next = self._next_smart

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

        # Note: this timeout is not the time-out used in the package request
        #       the timout here refers to the protocol time-out of this lib.
        rpc_response: RpcResponse = \
            await self._proto.get_dcom_response(
                request_pkg,
                size=RpcResponse.SIZE,
                timeout=self._timeout)

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

        # Note: this timeout is not the time-out used in the package request
        #       the timout here refers to the protocol time-out of this lib.
        rpc_response: RpcResponse = \
            await self._proto.get_dcom_response(
                request_pkg,
                size=RpcResponse.SIZE,
                timeout=self._timeout)

        message = rpc_response.get_message(self._proto)
        return NextBigResponse(message)

    async def release(self):
        try:
            await self._interface.rem_release(self._proto)
        except Exception:
            pass
        self.next = None
        self._interface = None
        self._proto = None
        self._class_parts.clear()

    done = release   # alias
