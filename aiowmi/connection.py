import logging
import asyncio
from typing import Optional, Callable
from Crypto.Cipher import ARC4
from .protocol import Protocol
from .dcom import Dcom
from .rpc.bind_ack import RpcBindAck
from .ntlm.auth_challange import NTLMAuthChallenge
from .ntlm.auth_authenticate import NTLMAuthAuthenticate
from .ntlm.auth_negotiate import NTLMAuthNegotiate
from .ntlm.tools import seal_func, sign_func
from .tools import get_rangom_bytes, encrypted_session_key
from .rpc.const import (
    RPC_C_AUTHN_LEVEL_CONNECT,
    RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
    RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
    RPC_C_AUTHN_WINNT
)
from .ntlm.const import (
    NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
    NTLMSSP_NEGOTIATE_KEY_EXCH,
)
from .ntlm.tools import (
    seal_func,
    seal_key,
    sign_func,
    sign_key,
)
from .ndr.remote_create_instance import RemoteCreateInstance
from .dcom_const import (
    CLSID_IWbemLevel1Login,
    IID_IRemoteSCMActivator,
    IID_IWbemLevel1Login,
    IID_IWbemServices,
)
from .rpc.request import RpcRequest
from .tools import pad4
from .rpc.response import RpcResponse
from .rpc.auth_verifier_co import RpcAuthVerifierCo
from .ndr.remote_create_instance_response import RemoteCreateInstanceResponse
from .ndr.ntlm_login_response import NTLMLoginResponse
from .ntlm.login import NTLMLogin


class Connection:

    def __init__(
            self,
            host: str,
            username: str,
            password: str,
            domain: str = '',
            port: int = 135,
            loop: Optional[asyncio.AbstractEventLoop] = None):
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._domain = domain
        self._loop = asyncio.get_event_loop() if loop is None else loop
        self._protocol: Optional[Protocol] = None
        self._timeout: int = 10
        self._namespace: Optional[str] = None

    async def connect(self, timeout: int = 10):
        conn = self._loop.create_connection(
            lambda: Protocol(loop=self._loop),
            host=self._host,
            port=self._port)

        _, self._protocol = await asyncio.wait_for(
            conn,
            timeout=timeout)
        self._timeout = timeout

    def close(self):
        if self._protocol:
            self._protocol.close()
        self._protocol = None

    def is_connected(self) -> bool:
        return bool(self._protocol)

    def connection_info(self) -> str:
        if not self.is_connected():
            return 'disconnected'
        return self._protocol.connection_info()

    async def _bind(self, iid: bytes, proto: Protocol):
        ntlm_auth_negotiate = NTLMAuthNegotiate()

        ntlm_negotiate_pkg = \
            proto._dcom.get_negotiate_ntlm_pkg(
                iid,
                ntlm_auth_negotiate,
                proto._auth_level)

        rpc_bind_ack: RpcBindAck = \
            await proto.get_dcom_response(
                ntlm_negotiate_pkg,
                timeout=self._timeout)

        proto._auth_type = rpc_bind_ack.auth.auth_type
        proto._auth_level = rpc_bind_ack.auth.auth_level

        ntlm_auth_challenge = NTLMAuthChallenge(rpc_bind_ack.auth.auth_value)
        proto._flags = flags = ntlm_auth_negotiate.get_negotiate_flags()

        ntlm_auth_authenticate = NTLMAuthAuthenticate(flags)

        session_base_key = ntlm_auth_authenticate.set_credentials(
            self._username,
            self._password,
            ntlm_auth_challenge.target_info,
            ntlm_auth_challenge.server_challenge,
            domain_name=self._domain)

        assert flags == 3767042613

        if flags & NTLMSSP_NEGOTIATE_KEY_EXCH:
            exported_session_key = get_rangom_bytes(16)

            encr_random_session_key = encrypted_session_key(
                session_base_key, exported_session_key)

            ntlm_auth_authenticate.set_encr_random_session_key(
                encr_random_session_key)
        else:
            exported_session_key = session_base_key

        ntlm_auth_authenticate.set_workstation_name(self._host)

        if proto._auth_level in (
                RPC_C_AUTHN_LEVEL_CONNECT,
                RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
                RPC_C_AUTHN_LEVEL_PKT_PRIVACY):
            if proto._auth_type == RPC_C_AUTHN_WINNT:
                if flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
                    client_signing_key = sign_key(
                        flags,
                        exported_session_key)
                    server_signing_key = sign_key(
                        flags,
                        exported_session_key,
                        client_mode=False)
                    client_sealing_key = seal_key(
                        flags,
                        exported_session_key)
                    server_sealing_key = seal_key(
                        flags,
                        exported_session_key,
                        client_mode=False)

                    client_sealing_handle = \
                        ARC4.new(client_sealing_key).encrypt
                    server_sealing_handle = \
                        ARC4.new(server_sealing_key).encrypt

                    proto._client_seal = seal_func(
                        client_signing_key,
                        client_sealing_handle)
                    proto._server_seal = seal_func(
                        server_signing_key,
                        server_sealing_handle)
                    proto._client_sign = sign_func(
                        client_signing_key,
                        client_sealing_handle)
                    proto._server_sign = sign_func(
                        server_signing_key,
                        server_sealing_handle)

        ntlm_auth_pkg = \
            proto._dcom.get_authenticate_ntlm_pkg(
                ntlm_auth_authenticate,
                proto._auth_level)

        proto.write(ntlm_auth_pkg)

    async def negotiate_ntlm(self) -> Protocol:
        proto = self._protocol
        proto._auth_level = RPC_C_AUTHN_LEVEL_PKT_PRIVACY

        await self._bind(IID_IRemoteSCMActivator, proto)

        remote_create_instance = RemoteCreateInstance(
            CLSID_IWbemLevel1Login,
            IID_IWbemLevel1Login)

        rci_pkg = remote_create_instance.get_data()

        request = RpcRequest(op_num=4)
        request.set_pdu_data(rci_pkg)

        request_pkg = request.seal_data(proto)

        rpc_response: RpcResponse = \
            await proto.get_dcom_response(
                request_pkg,
                size=RpcResponse.SIZE,
                timeout=self._timeout)

        message = rpc_response.get_message(proto)

        interface = RemoteCreateInstanceResponse(self._host, message)

        proto._interface = interface
        proto._iid = IID_IWbemLevel1Login

        host, port = interface.get_binding()

        try:
            conn = self._loop.create_connection(
                lambda: Protocol(loop=self._loop),
                host=self._host,
                port=port)

            _, proto = await asyncio.wait_for(
                conn,
                timeout=self._timeout)
        except Exception as e:
            logging.warning(
                f'failed to connect to {self._host} ({port}); '
                f'fallback to {host} ({port})...')

            conn = self._loop.create_connection(
                lambda: Protocol(loop=self._loop),
                host=host,
                port=port)

            _, proto = await asyncio.wait_for(
                conn,
                timeout=self._timeout)

        proto._auth_level = max(
            interface.scm_reply_info_data.authn_hint,
            RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)

        await self._bind(IID_IWbemLevel1Login, proto)

        return proto

    async def login_ntlm(
            self,
            proto: Protocol,
            namespace: str = 'root/cimv2'):
        if not namespace.startswith('//'):
            namespace = '//./' + namespace
        ntlm_login = NTLMLogin(namespace)
        ntlm_login_pkg = ntlm_login.get_data()
        interface = self._protocol._interface

        request = RpcRequest(op_num=6, uuid_str=interface.get_ipid())

        request.set_pdu_data(ntlm_login_pkg)

        request_pkg = request.sign_data(proto)

        rpc_response: RpcResponse = \
            await proto.get_dcom_response(
                request_pkg,
                size=RpcResponse.SIZE,
                timeout=self._timeout)

        message = rpc_response.get_message(proto)

        ntlm_login_resp = NTLMLoginResponse(message)

        proto._interface = ntlm_login_resp
        proto._interface.scm_reply_info_data = interface.scm_reply_info_data
        self._iid = IID_IWbemServices
        self._namespace = namespace
