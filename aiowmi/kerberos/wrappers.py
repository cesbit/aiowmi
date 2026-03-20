import functools
from typing import Tuple
from .gss import gss_wrap_rc4, gss_wrap_aes, gss_unwrap_rc4, gss_unwrap_aes


def seal_func_kerberos(session_key: bytes, etype: int):
    def _sealer_rc4(
            flags: int,
            seq_num: int,
            message_to_sign: bytes,
            message_to_encrypt: bytes,
            session_key: bytes) -> Tuple[bytes, bytes]:
        return gss_wrap_rc4(session_key,
                            message_to_encrypt,
                            seq_num)

    def _sealer_aes(
            flags: int,
            seq_num: int,
            message_to_sign: bytes,
            message_to_encrypt: bytes,
            session_key: bytes) -> Tuple[bytes, bytes]:
        return gss_wrap_aes(session_key,
                            message_to_encrypt,
                            seq_num)
    if etype in (17, 18):
        sealer = _sealer_aes
    elif etype == 23:
        sealer = _sealer_rc4
    else:
        raise ValueError(f"Invalid E-type: {etype}")
    return functools.partial(sealer, session_key=session_key)


def gss_unwrap_kerberos(session_key: bytes, etype: int):
    def _unwrap_rc4(
            cipher_text: bytes,
            auth_data: bytes,
            session_key: bytes) -> bytes:
        return gss_unwrap_rc4(session_key,
                              cipher_text,
                              auth_data)

    def _unwrap_aes(
            cipher_text: bytes,
            auth_data: bytes,
            session_key: bytes) -> bytes:
        return gss_unwrap_aes(session_key,
                              cipher_text,
                              auth_data)
    if etype in (17, 18):
        unwrapper = _unwrap_aes
    elif etype == 23:
        unwrapper = _unwrap_rc4
    else:
        raise ValueError(f"Invalid E-type: {etype}")
    return functools.partial(unwrapper, session_key=session_key)


def sign_func_kerberos(session_key: bytes, etype: int):
    def _signer_rc4(
            flags: int,
            seq_num: int,
            message_to_sign: bytes,
            session_key: bytes) -> Tuple[bytes, bytes]:
        return gss_wrap_rc4(session_key,
                            message_to_sign,
                            seq_num)

    def _signer_aes(
            flags: int,
            seq_num: int,
            message_to_sign: bytes,
            session_key: bytes) -> Tuple[bytes, bytes]:
        return gss_wrap_aes(session_key,
                            message_to_sign,
                            seq_num)
    if etype in (17, 18):
        signer = _signer_aes
    elif etype == 23:
        signer = _signer_rc4
    else:
        raise ValueError(f"Invalid E-type: {etype}")
    return functools.partial(signer, session_key=session_key)
