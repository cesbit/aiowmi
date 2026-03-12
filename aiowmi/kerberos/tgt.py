import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from .as_req import build_as_req, build_full_as_req
from .kdc import send_kerberos_packet
from .asn1 import get_asn1_len
from .tools import parse_krb_error


def extract_kerberos_salt(error_data: bytes) -> str:
    if error_data[0] != 0x7e:
        raise ValueError("Invalid KRB-ERROR packet")

    # find start of container
    e_data_idx = error_data.find(b'\xac')
    if e_data_idx == -1:
        raise ValueError("e-data (Tag 12) niet gevonden")

    pos = e_data_idx
    _, len_size = get_asn1_len(error_data, pos + 1)
    pos += 1 + len_size

    salt_tag_idx = error_data.find(b'\x1b\x1c', pos)
    if salt_tag_idx == -1:
        raise ValueError("Salt (GeneralString) not found")

    salt_len, salt_len_size = get_asn1_len(error_data, salt_tag_idx + 1)
    salt_start = salt_tag_idx + 1 + salt_len_size

    salt_bytes = error_data[salt_start: salt_start + salt_len]
    return salt_bytes.decode('utf-8')


def nfold_for_kerberos():
    return b'\x6b\x65\x72\x62\x65\x72\x6f\x73\x7b\x9b\x5b\x2b\x93\x13\x2b\x93'


def aes_string_to_key(password, salt):
    tkey = hashlib.pbkdf2_hmac('sha1',
                               password.encode(),
                               salt.encode(),
                               4096,
                               32)
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
                  kdc_host: str, kdc_port: int = 88) -> tuple[bytes, bytes]:
    as_req = build_as_req(username, domain)
    resp = await send_kerberos_packet(as_req, kdc_host, kdc_port)
    parse_krb_error(resp)
    salt = extract_kerberos_salt(resp)
    base_key = aes_string_to_key(password, salt)
    full_as_req = build_full_as_req(username, domain, base_key)
    as_res_bytes = await send_kerberos_packet(full_as_req, kdc_host, kdc_port)
    parse_krb_error(as_res_bytes)
    return as_res_bytes, base_key
