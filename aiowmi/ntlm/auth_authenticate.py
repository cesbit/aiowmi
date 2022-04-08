import struct
from ..tools import get_rangom_bytes, ntowf_v2, hmac_md5
from .av_pairs import AvPairs
from .version import NTLMVersion
from .const import NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED
from .const import NTLMSSP_NEGOTIATE_VERSION


# 2.2.1.3 AUTHENTICATE_MESSAGE
class NTLMAuthAuthenticate:
    """Message from client to server."""

    SIGNATURE = b'NTLMSSP\x00'
    SIGNATURE_LEN = len(SIGNATURE)
    MESSAGE_TYPE = 3
    AUTHENTICATE_FMT = '<LHHLHHLHHLHHLHHLHHLL'
    AUTHENTICATE_SIZE = SIGNATURE_LEN + struct.calcsize(AUTHENTICATE_FMT)

    def __init__(self, negotiate_flags):
        self._negotiate_flags = negotiate_flags
        self._version = b''
        self._version_len = 0
        self._mic = b''     # Message integrity, NTLMSSP_MESSAGE_SIGNATURE
        self._mic_len = 0   # Message integrity length is 16 when set
        self._lm_challenge_response = b''
        self._lm_challenge_response_len = 0
        self._nt_challenge_response = b''
        self._nt_challenge_response_len = 0
        self._domain_name = b''
        self._domain_name_len = 0
        self._user_name = b''
        self._user_name_len = 0
        self._workstation_name = b''
        self._workstation_name_len = 0
        self._encr_random_session_key = b''
        self._encr_random_session_key_len = 0

    def set_version(self, version: NTLMVersion):
        """Version is packed as 8 bytes.
        So:
          len(self._version) ==  NTLMVersion.VERSION_SIZE == 8 bytes
        """
        self._version = version.get_data()
        self._version_len = NTLMVersion.VERSION_SIZE
        self._negotiate_flags |= NTLMSSP_NEGOTIATE_VERSION

    def set_credentials(
            self,
            user_name: str,
            password: str,
            target_info: bytes,
            server_challenge: bytes,
            domain_name: str = '') -> bytes:
        self._user_name = user_name.encode('utf-16le')
        self._user_name_len = len(self._user_name)

        self._domain_name = domain_name.encode('utf-16le')
        self._domain_name_len = len(self._domain_name)

        response_key_nt = ntowf_v2(user_name, password, self._domain_name)

        av_pairs = AvPairs(target_info)
        av_pairs.set_target_name()
        av_time = av_pairs.get_or_set_av_time()

        client_challenge = get_rangom_bytes(8)
        server_name = av_pairs.get_data()

        temp = b''.join((
            b'\x01\x01\x00\x00\x00\x00\x00\x00',
            av_time,
            client_challenge,
            b'\x00\x00\x00\x00',
            server_name,
            b'\x00\x00\x00\x00'))

        nt_proof_str = hmac_md5(response_key_nt, server_challenge + temp)

        self._lm_challenge_response = hmac_md5(
            response_key_nt,
            server_challenge + client_challenge) + client_challenge
        self._nt_challenge_response = nt_proof_str + temp

        session_base_key = hmac_md5(response_key_nt, nt_proof_str)

        self._lm_challenge_response_len = len(self._lm_challenge_response)
        self._nt_challenge_response_len = len(self._nt_challenge_response)

        return session_base_key

    def set_workstation_name(self, workstation_name):
        self._workstation_name = workstation_name.encode('utf-16le')
        self._workstation_name_len = len(self._workstation_name)
        self._negotiate_flags |= NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED

    def set_encr_random_session_key(self, encr_random_session_key: bytes):
        self._encr_random_session_key = encr_random_session_key
        self._encr_random_session_key_len = len(self._encr_random_session_key)

    def get_data(self) -> bytes:
        domain_name_offset = \
            self.AUTHENTICATE_SIZE + self._version_len + self._mic_len
        user_name_offset = \
            domain_name_offset + self._domain_name_len
        workstation_name_offset = \
            user_name_offset + self._user_name_len
        lm_challenge_response_offset = \
            workstation_name_offset + self._workstation_name_len
        nt_challenge_response_offset = \
            lm_challenge_response_offset + self._lm_challenge_response_len
        encr_random_session_key_offset = \
            nt_challenge_response_offset + self._nt_challenge_response_len

        data = struct.pack(
            self.AUTHENTICATE_FMT,
            self.MESSAGE_TYPE,                  # <L
            self._lm_challenge_response_len,    # <H
            self._lm_challenge_response_len,    # <H  (max len, equal to len)
            lm_challenge_response_offset,       # <L
            self._nt_challenge_response_len,    # <H
            self._nt_challenge_response_len,    # <H  (max len, equal to len)
            nt_challenge_response_offset,       # <L
            self._domain_name_len,              # <H
            self._domain_name_len,              # <H  (max len, equal to len)
            domain_name_offset,                 # <L
            self._user_name_len,                # <H
            self._user_name_len,                # <H  (max len, equal to len)
            user_name_offset,                   # <L
            self._workstation_name_len,         # <H
            self._workstation_name_len,         # <H  (max len, equal to len)
            workstation_name_offset,            # <L
            self._encr_random_session_key_len,  # <H NTLMSSP_NEGOTIATE_KEY_EXCH
            self._encr_random_session_key_len,  # <H  (max len, equal to len)
            encr_random_session_key_offset,     # <L
            self._negotiate_flags,              # <L
        )
        data = b''.join([
            self.SIGNATURE,
            data,
            self._version,
            self._mic,
            self._domain_name,
            self._user_name,
            self._workstation_name,
            self._lm_challenge_response,
            self._nt_challenge_response,
            self._encr_random_session_key
        ])
        return data
