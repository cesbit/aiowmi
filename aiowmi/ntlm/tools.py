import hashlib
import string
import functools
from typing import Callable, Tuple
from .message_signature import NTLMMessageSignature
from .const import (
    NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
    NTLMSSP_NEGOTIATE_128,
    NTLMSSP_NEGOTIATE_56,
)


SIGN_CLIENT_SERVER = \
    b'session key to client-to-server signing key magic constant\x00'
SIGN_SERVER_CLIENT = \
    b'session key to server-to-client signing key magic constant\x00'


SEAL_CLIENT_SERVER = \
    b'session key to client-to-server sealing key magic constant\x00'
SEAL_SERVER_CLIENT = \
    b'session key to server-to-client sealing key magic constant\x00'


def sign_key(flags: int, random_session_key: bytes, client_mode: bool = True):
    if not (flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY):
        return None

    md5 = hashlib.new('md5')
    if client_mode:
        md5.update(random_session_key + SIGN_CLIENT_SERVER)
    else:
        md5.update(random_session_key + SIGN_SERVER_CLIENT)
    return md5.digest()


def seal_key(flags: int, random_session_key: bytes, client_mode: bool = True):
    if flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
        if flags & NTLMSSP_NEGOTIATE_128:
            seal_key = random_session_key
        elif flags & NTLMSSP_NEGOTIATE_56:
            seal_key = random_session_key[:7]
        else:
            seal_key = random_session_key[:5]

        md5 = hashlib.new('md5')
        if client_mode:
            md5.update(seal_key + SEAL_CLIENT_SERVER)
        else:
            md5.update(seal_key + SEAL_SERVER_CLIENT)
        return md5.digest()

    if flags & NTLMSSP_NEGOTIATE_56:
        return random_session_key[:7] + b'\xa0'

    return random_session_key[:5] + b'\xe5\x38\xb0'


def _seal(
        flags: int,
        seq_num: int,
        message_to_sign: bytes,
        message_to_encrypt: bytes,
        signing_key: bytes,
        handle: Callable) -> Tuple[bytes, bytes]:
    sealed_message = handle(message_to_encrypt)
    message_signature = NTLMMessageSignature.get_data(
        flags,
        seq_num,
        message_to_sign,
        signing_key,
        handle)
    return sealed_message, message_signature


def seal_func(
            signing_key: bytes,
            handle: Callable[[bytes, bytes], bytes],
        ) -> Callable[
            [int, int, bytes, bytes],
            Tuple[bytes, bytes]]:
    return functools.partial(
        _seal,
        signing_key=signing_key,
        handle=handle)


def sign_func(
            signing_key,
            handle: Callable
        ) -> Callable[[int, int, bytes], bytes]:
    return functools.partial(
        NTLMMessageSignature.get_data,
        signing_key=signing_key,
        handle=handle)
