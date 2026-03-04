import asyncio
import pickle
from typing import Optional, Callable
from Crypto.Cipher import ARC4
from .protocol import Protocol
from .dcom import Dcom
from .rpc.bind_ack import RpcBindAck
from .kerberos.tgt import get_tgt
from .kerberos.tgs import get_tgs
from .kerberos.ap_req import build_ap_req, wrap_gss_kerberos
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
from .rpc.response import RpcResponse
from .ndr.remote_create_instance_response import RemoteCreateInstanceResponse
from .ndr.ntlm_login_response import NTLMLoginResponse
from .ntlm.login import NTLMLogin
from .logger import logger


class Connection:

    def __init__(
            self,
            host: str,
            username: str,
            password: str,
            domain: str = '',
            port: int = 135,
            kdc_host: Optional[str] = None,
            kdc_port: int = 88,
            kerberos_cache_file: Optional[str] = None,
            loop: Optional[asyncio.AbstractEventLoop] = None):
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._domain = domain
        self._kdc_host = kdc_host or self._host
        self._kdc_port = kdc_port
        self._loop = asyncio.get_event_loop() if loop is None else loop
        self._protocol: Optional[Protocol] = None
        self._timeout: int = 10
        self._namespace: Optional[str] = None
        self._tgt: Optional[tuple[bytes, bytes]] = None
        self._tgs: Optional[tuple[bytes, bytes]] = None
        self._kerberos_cache_file = kerberos_cache_file
        if kerberos_cache_file:
            try:
                with open(kerberos_cache_file, 'rb') as fp:
                    dump = pickle.load(fp)
                self._tgt = dump[0], dump[1]
                self._tgs = dump[2], dump[3]
            except Exception:
                logger.warning(f'failed to load from: {kerberos_cache_file}')

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

    async def _bind_ntlm(self, iid: bytes, proto: Protocol):
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

    async def _negotiate_kerberos(self):
        self._tgt = await get_tgt(self._username,
                                  self._password,
                                  self._domain,
                                  self._kdc_host,
                                  self._kdc_port)
        self._tgs = await get_tgs(self._username,
                                  self._domain,
                                  self._host,
                                  *self._tgt,
                                  self._kdc_host,
                                  self._kdc_port)

        if self._kerberos_cache_file:
            try:
                with open(self._kerberos_cache_file, 'wb') as fp:
                    pickle.dump(self._tgt + self._tgs, fp)
            except Exception as e:
                logger.warning(
                    f'failed to write to: {self._kerberos_cache_file}: {e}')

    async def negotiate_kerberos(self) -> Protocol:
        proto = self._protocol
        proto._auth_level = RPC_C_AUTHN_LEVEL_PKT_PRIVACY

        if not self._domain:
            raise Exception('domain is required for Kerberos authentication')

        if self._tgt is None or self._tgt is None:
            await self._negotiate_kerberos()

        await self._bind_kerberos(IID_IWbemLevel1Login, proto)

    async def _bind_kerberos(self, iid: bytes, proto: Protocol):
        ticket, service_session_key = self._tgs
        # ticket and service_session_key are equal in length [CHECK]

        ap_req = build_ap_req(self._username,
                              self._domain,
                              ticket, service_session_key)
        # print(f'[D] AP_REQ ({len(ap_req)}) HEX: {ap_req.hex()}')

        auth_value = wrap_gss_kerberos(ap_req)
        # print(f'[D] AUTH_VALUE ({len(auth_value)}) HEX: {auth_value.hex()}')
        # print(f'[D] AUTH IMPACKET (1634) HEX: 6082065e06062b0601050502a08206523082064ea00d300b06092a864882f712010202a282063b048206376082063306092a864886f71201020201006e8206223082061ea003020105a10302010ea20703050020000000a3820557618205533082054fa003020105a1181b164c41422e544553542d544543484e4f4c4f47592e4e4ca23c303aa003020102a13330311b04686f73741b29646f6d61696e636f6e74726f6c6c657230312e6c61622e746573742d746563686e6f6c6f67792e6e6ca38204ee308204eaa003020112a103020135a28204dc048204d83420a7b6dce9cc4087c3d226ee335636868792308b112c62b273b9a8c87004cecf9f8fb1e3b3e90f8770584a1741d74fa5dc2ea8a308f329ac08b46fd17485cafe660ec8bdf793093648f2b7b64c2e695e0cf905ba6003a76f02a3faba314f10a741d46bb6a7dbbf3a20fe90a40deb3c826966a86e3ff398e5fa755efb3a0f485c892fcda4a3e968dfd538519ffc2b7cb9170ba98558dd16fae6a684fbd0107e055792cb6192b03a7cebc123bee490d7c0d33d1b40d16e6970ade252bbdc720e07730e9de84b0e79cfb94120487988c97be5c6325f8c3c6e42601a005ac4793de32de2392924bf0617e4967471322bf03f4939306bf9104956e91a400b82e3d9c66434c81e530c26f4c9146f6e06f9897dd0d86de977fc82974570e083aae6ebc7d8b86e1588e934be604478c3fbe34699536730121bddf078d01837ad9cd8aaaa639b1ececb9ecbcb05ce2f8a7ad723e4a06c1f5673fb089b6ea7a9b376f2acc495103db002ab58451dcaf76198e2ed515504f50cfcc67103c9a686e415d64f7b3e1b214f47fcf8d6123ecb8fc34379b1c0ce3d005aa071b54cab414102a3767d3fab2bad0d7d28e6a3e2f099ac958f6346fa61e78965b9550912a9f4d80ab9c59d2f8b687e47d16918b592e30d291f99f827551781bb9cd67d1438830f8cc6c99c131faf708f8fc83a4cc5285bf512c5fa398dc5def8f1842a43086a49006409157b3ac1b66e2dadddfeaf52c7ebfe1ad746a48b920be5ebb876e0b7b1d563a863969e56a35e9fe394b6d6a8bb453f6427fe408e76505ca70048799e1cb1c9a995a93518298fab04237433d7f7fc44b89cda39c1288bdaddd5716c6c99eafa92e2a7e90b04600c7b762a87da9b9623c061797a3472c7ff0c6f28ffcf48d04ba484095c3379aa3042356e158d5890bc8afb2114504de649b1719844ee8311e618c23ef12528c4dfe739d11c13109f8529808ca1c0a25acffff2ae35e13fbc745bff195181413afd05b804bbc4c6e60e370ad06696c6d633c77cb8248806035848cbb051c59022f5292542849b2c8d4e29df79950b1809aafea72a524059adc4445c1c119442257d2a293781153aee9935b5da952d9339d08154de97b4db6cf2583be50de38e209f1cd91cbb86e8f7ef34f7f0729dc3a998421768623d6280fd44b56061e98859a78e0179c8b25ca9bb84dad68d7008d0c93bf74b1c5e2f782272a66f44bdf263f167b740a2192c09f2be3640fc33a31120b4db77a05fec6339a5b7a463e74f4ffa908dfb65fae3eff75174e86d29e92d130f0c00b253d42b7fdcc6f2c09197ae6d1e28be58ba9082a04a9c7e770f2a9864b1c066a2584e1d96e2b6bbcff03ad96e0b1a0a4d4929d7268396287decbc9e53cdf492c98bd0baf465b9a8be1c4221db2946dde9dfc75594862816da88ee66289a7e09fad3f60363002ec856523dc347ae5d325b1ebca30e766d400f906ac5b285eb1369e7bf1b776cddc1dee550efce3dc75f8aeb56a1c887aa173f74e650263c309c642e70e115e2dc526c08ae0c52b6bf1c4eabf7f040c291245354eedca386be5bfbd3c084dc594cc17bc4741a4e12173a0b5131d8a2b9c657fff4faa80e7ff1c2f7d95e90a81f577aa577ad0e55f6dd372f8767a2c4a445a24685d498a3ac32fe675b3e12bd6d1f6d95ef14b2817b1911358bb12e52453afadf5075bd90cb26248730aaaccc8f9d96e71b188992c45be7e09006fe26016c469db90e4612a481ad3081aaa003020117a281a204819fb15d434808309ed7b4f5c5d24105a8a4223be9d634de5f42665d4456c8c6335486c7eddd67ae9c15f9a2d682f95de3070dc8254233513f93c8216c2400b7329cccc10c41ba872944f7a3e4ccd48c7d154da3c92752f908524401a52a2a3028b8a13f8c2c1dd9260119d5323357ba1044330aa59fe559562ece294517c791e72d378a72688b870d02d41b5f60c926d8bad9020c5a77418c4bc643fa49593430')

        bind_pkg = proto._dcom.get_bind_kerberos_pkg(
            iid,
            auth_value,
            proto._auth_level,
        )
        # print(f'[I] IMPACKET BIND PKG (1714) HEX: 05000b0310000000b206620601000000b810b810000000000100000000000100a001000000000000c00000000000004600000000045d888aeb1cc9119fe808002b10486002000000090600007f3501006082065e06062b0601050502a08206523082064ea00d300b06092a864882f712010202a282063b048206376082063306092a864886f71201020201006e8206223082061ea003020105a10302010ea20703050020000000a3820557618205533082054fa003020105a1181b164c41422e544553542d544543484e4f4c4f47592e4e4ca23c303aa003020102a13330311b04686f73741b29646f6d61696e636f6e74726f6c6c657230312e6c61622e746573742d746563686e6f6c6f67792e6e6ca38204ee308204eaa003020112a103020135a28204dc048204d83420a7b6dce9cc4087c3d226ee335636868792308b112c62b273b9a8c87004cecf9f8fb1e3b3e90f8770584a1741d74fa5dc2ea8a308f329ac08b46fd17485cafe660ec8bdf793093648f2b7b64c2e695e0cf905ba6003a76f02a3faba314f10a741d46bb6a7dbbf3a20fe90a40deb3c826966a86e3ff398e5fa755efb3a0f485c892fcda4a3e968dfd538519ffc2b7cb9170ba98558dd16fae6a684fbd0107e055792cb6192b03a7cebc123bee490d7c0d33d1b40d16e6970ade252bbdc720e07730e9de84b0e79cfb94120487988c97be5c6325f8c3c6e42601a005ac4793de32de2392924bf0617e4967471322bf03f4939306bf9104956e91a400b82e3d9c66434c81e530c26f4c9146f6e06f9897dd0d86de977fc82974570e083aae6ebc7d8b86e1588e934be604478c3fbe34699536730121bddf078d01837ad9cd8aaaa639b1ececb9ecbcb05ce2f8a7ad723e4a06c1f5673fb089b6ea7a9b376f2acc495103db002ab58451dcaf76198e2ed515504f50cfcc67103c9a686e415d64f7b3e1b214f47fcf8d6123ecb8fc34379b1c0ce3d005aa071b54cab414102a3767d3fab2bad0d7d28e6a3e2f099ac958f6346fa61e78965b9550912a9f4d80ab9c59d2f8b687e47d16918b592e30d291f99f827551781bb9cd67d1438830f8cc6c99c131faf708f8fc83a4cc5285bf512c5fa398dc5def8f1842a43086a49006409157b3ac1b66e2dadddfeaf52c7ebfe1ad746a48b920be5ebb876e0b7b1d563a863969e56a35e9fe394b6d6a8bb453f6427fe408e76505ca70048799e1cb1c9a995a93518298fab04237433d7f7fc44b89cda39c1288bdaddd5716c6c99eafa92e2a7e90b04600c7b762a87da9b9623c061797a3472c7ff0c6f28ffcf48d04ba484095c3379aa3042356e158d5890bc8afb2114504de649b1719844ee8311e618c23ef12528c4dfe739d11c13109f8529808ca1c0a25acffff2ae35e13fbc745bff195181413afd05b804bbc4c6e60e370ad06696c6d633c77cb8248806035848cbb051c59022f5292542849b2c8d4e29df79950b1809aafea72a524059adc4445c1c119442257d2a293781153aee9935b5da952d9339d08154de97b4db6cf2583be50de38e209f1cd91cbb86e8f7ef34f7f0729dc3a998421768623d6280fd44b56061e98859a78e0179c8b25ca9bb84dad68d7008d0c93bf74b1c5e2f782272a66f44bdf263f167b740a2192c09f2be3640fc33a31120b4db77a05fec6339a5b7a463e74f4ffa908dfb65fae3eff75174e86d29e92d130f0c00b253d42b7fdcc6f2c09197ae6d1e28be58ba9082a04a9c7e770f2a9864b1c066a2584e1d96e2b6bbcff03ad96e0b1a0a4d4929d7268396287decbc9e53cdf492c98bd0baf465b9a8be1c4221db2946dde9dfc75594862816da88ee66289a7e09fad3f60363002ec856523dc347ae5d325b1ebca30e766d400f906ac5b285eb1369e7bf1b776cddc1dee550efce3dc75f8aeb56a1c887aa173f74e650263c309c642e70e115e2dc526c08ae0c52b6bf1c4eabf7f040c291245354eedca386be5bfbd3c084dc594cc17bc4741a4e12173a0b5131d8a2b9c657fff4faa80e7ff1c2f7d95e90a81f577aa577ad0e55f6dd372f8767a2c4a445a24685d498a3ac32fe675b3e12bd6d1f6d95ef14b2817b1911358bb12e52453afadf5075bd90cb26248730aaaccc8f9d96e71b188992c45be7e09006fe26016c469db90e4612a481ad3081aaa003020117a281a204819fb15d434808309ed7b4f5c5d24105a8a4223be9d634de5f42665d4456c8c6335486c7eddd67ae9c15f9a2d682f95de3070dc8254233513f93c8216c2400b7329cccc10c41ba872944f7a3e4ccd48c7d154da3c92752f908524401a52a2a3028b8a13f8c2c1dd9260119d5323357ba1044330aa59fe559562ece294517c791e72d378a72688b870d02d41b5f60c926d8bad9020c5a77418c4bc643fa49593430')
        # print(f'[D] MY BIND PKG ({len(bind_pkg)}) HEX: {bind_pkg.hex()}')

        rpc_bind_ack = await proto.get_dcom_response(bind_pkg)
        assert 0
        print(f'[D] BIND ACK ({len(rpc_bind_ack)}) HEX: {rpc_bind_ack.hex()}')
        if proto._auth_level >= RPC_C_AUTHN_LEVEL_PKT_INTEGRITY:
            proto._client_sign = kerberos_sign_func(service_session_key)
            proto._client_seal = kerberos_seal_func(service_session_key)


    async def negotiate_ntlm(self) -> Protocol:
        proto = self._protocol
        proto._auth_level = RPC_C_AUTHN_LEVEL_PKT_PRIVACY

        await self._bind_ntlm(IID_IRemoteSCMActivator, proto)

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
            logger.warning(
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

        await self._bind_ntlm(IID_IWbemLevel1Login, proto)

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
