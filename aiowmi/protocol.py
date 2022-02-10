import logging
import asyncio
import struct
from typing import Optional, Callable
from .dcom import Dcom
from .rpc.common import RpcCommon
from .rpc.response import RpcResponse
from .rpc.request import RpcRequest
from .rpc.fault import RpcFault
from .ndr.interface import NdrInterface
from .rpc.const import PFC_LAST_FRAG
from .rpc.baseresp import RpcBaseResp
from .request import Request
from .exceptions import DcomException
from .buf import Buf

class Protocol(asyncio.Protocol):

    def __init__(self, loop: Optional[asyncio.AbstractEventLoop] = None):
        self._transport = None
        self._fut = None
        self._size = None
        self._buf = None
        self._interface: NdrInterface = None
        self._auth_type: int = None
        self._auth_level: int = None
        self._flags = None
        self._client_seal: Optional[Callable] = None
        self._server_seal: Optional[Callable] = None
        self._dcom = Dcom()
        self._iid = None
        self._requests = {}

    @staticmethod
    def get_call_id(data: bytes):
        call_id, = struct.unpack_from('<L', data, offset=12)
        return call_id

    def connection_made(self, transport: asyncio.Transport) -> None:
        '''
        override asyncio.Protocol
        '''
        logging.info('Connection made')
        self._transport = transport

    def connection_lost(self, exc: Exception) -> None:
        '''
        override asyncio.Protocol
        '''
        logging.info('Connection lost')
        self._transport = None

    def __bool__(self):
        return self._transport is not None

    def data_received(self, data: bytes) -> None:
        '''
        override asyncio.Protocol
        '''
        if self._buf is None:
            size, _, call_id, = struct.unpack_from('<HHL', data, offset=8)
            self._buf = Buf(size, call_id)

        more = self._buf.append(data)

        if more is False:
            return None

        req, data, = self._requests[self._buf.call_id], self._buf.data

        self._buf = None

        if req.size is not None:
            assert req.fut  # when size is set, we must have a future
            req.buf += data

            if len(req.buf) < req.size:
                if more:
                    self.data_received(more)
                return

            data = req.buf[:req.size]
            rest = req.buf[req.size:]
            req.size = None
            req.buf = rest

        if req.fut:
            req.fut.set_result(data)
            req.fut = None
        elif data:
            req.buf += data

        if more:
            self.data_received(more)

    def write(self, data: bytes):
        # call_id, = struct.unpack_from('<L', data, offset=12)
        # print('SEND!! Call Id:', call_id)
        # print(data)
        self._transport.write(data)

    def connection_info(self) -> str:
        if self._transport is None:
            return 'disconnected'
        socket = self._transport.get_extra_info('socket', None)
        if socket is None:
            return 'unknown_addr'
        addr, port = socket.getpeername()[:2]
        return f'{addr}:{port}'

    def close(self):
        if self._transport is None:
            return
        self._transport.close()

    async def get_dcom_response(
            self,
            request: bytes,
            size: Optional[int] = None) -> RpcBaseResp:
        req = Request(size=size)
        call_id = self.get_call_id(request)

        assert call_id not in self._requests
        self._requests[call_id] = req
        try:
            pdu_data_list = []
            self.write(request)

            data = await req.fut

            while True:
                rpc_common = RpcCommon.from_data(data)
                ndata = len(data)

                callback = self._dcom._DCOM_RPC_MAP.get(rpc_common.ptype)
                if callback is None:
                    raise DcomException(f'Unknown ptype: {rpc_common.ptype}')
                response = callback(self._dcom, rpc_common, data)

                n = response.rpc_common.frag_length
                if n > ndata:
                    n -= RpcResponse.SIZE
                    resp = await req.readn(n)
                    pdu_data_list.append((resp, n))

                if rpc_common.pfc_flags & PFC_LAST_FRAG:
                    break

                data = await req.readn(size)

            if pdu_data_list:
                response.set_pdu_data_list(pdu_data_list)

            if isinstance(response, RpcFault):
                response.throw()

        finally:
            self._requests.pop(call_id)

        return response

    async def rem_release(self):
        assert self._interface, 'Protocol must have an interface'
        request = RpcRequest(op_num=5, uuid_str=self._interface.get_ipid())

        return self._dcom.rem_releae()
