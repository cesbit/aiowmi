from .as_req import build_as_req, build_full_as_req
from .kdc import send_kerberos_packet
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def extract_kerberos_salt(error_data: bytes) -> str:
    """
    Extract salt from KRB-ERROR (0x7e) response.
    PA-ETYPE-INFO2 (Tag 19).
    """
    try:
        start_marker = b'\x1b\x1c'
        if start_marker in error_data:
            offset = error_data.find(start_marker) + 2
            salt = error_data[offset:offset+28].decode('utf-8')
            return salt
    except Exception:
        pass
    raise Exception('failed to get salt')


def nfold_for_kerberos():
    return b'\x6b\x65\x72\x62\x65\x72\x6f\x73\x7b\x9b\x5b\x2b\x93\x13\x2b\x93'


def aes_string_to_key(password, salt):
    tkey = hashlib.pbkdf2_hmac('sha1', password.encode(), salt.encode(), 4096, 32)
    constant = nfold_for_kerberos()

    # Gebruik AES-256 CBC met IV=0
    cipher = Cipher(algorithms.AES(tkey), modes.CBC(b'\x00' * 16))

    # Deel 1 van de definitieve sleutel
    encryptor1 = cipher.encryptor()
    part1 = encryptor1.update(constant) + encryptor1.finalize()

    # Deel 2 van de definitieve sleutel (met part1 als nieuwe input)
    encryptor2 = cipher.encryptor()
    part2 = encryptor2.update(part1) + encryptor2.finalize()

    return part1 + part2


async def get_tgt(username: str, password: str, domain: str,
                  kdc_host: str, kdc_port: int = 88):
    as_req = build_as_req(username, domain)
    resp = await send_kerberos_packet(as_req, kdc_host, kdc_port)
    salt = extract_kerberos_salt(resp)
    key = aes_string_to_key(password, salt)
    full_as_req = build_full_as_req(username, domain, key)
    resp = await send_kerberos_packet(full_as_req, kdc_host, kdc_port)
    print(f'Response: {resp}')
    assert 0