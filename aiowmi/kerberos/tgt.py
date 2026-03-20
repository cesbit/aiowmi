from typing import Tuple
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Hash import SHA1
from .as_req import build_as_req, build_full_as_req
from .kdc import send_kerberos_packet
from .tools import parse_krb_error, peel_tag


def extract_salt_and_etype(error_data: bytes) -> Tuple[str, int]:
    if error_data[0] != 0x7e:
        raise ValueError("Invalid KRB-ERROR packet")

    e_data_idx = error_data.find(b'\xac')
    if e_data_idx == -1:
        raise ValueError("e-data (Tag 12) not found in KRB-ERROR")

    etype_18_marker = b'\x02\x01\x12'
    marker_idx = error_data.find(etype_18_marker, e_data_idx)

    etype = 18
    if marker_idx == -1:
        etype_17_marker = b'\x02\x01\x11'
        marker_idx = error_data.find(etype_17_marker, e_data_idx)
        etype = 17

    if marker_idx == -1:
        raise ValueError("No AES (17/18) etype found in e-data")

    salt_tag_idx = error_data.find(b'\xa1', marker_idx)
    if salt_tag_idx == -1:
        raise ValueError(f"Salt tag (0xa1) not found for etype {etype}")

    salt_start_idx = -1
    for tag in [b'\x1b', b'\x04', b'\x1d']:
        tag_pos = error_data.find(tag, salt_tag_idx, salt_tag_idx + 15)
        if tag_pos != -1:
            salt_start_idx = tag_pos
            break

    if salt_start_idx == -1:
        raise ValueError(
            "Could not find string tag (1b/04) within salt container")

    pos = salt_start_idx + 1
    length_byte = error_data[pos]
    pos += 1

    if length_byte & 0x80:
        n_bytes = length_byte & 0x7f
        salt_len = int.from_bytes(error_data[pos: pos + n_bytes], 'big')
        pos += n_bytes
    else:
        salt_len = length_byte

    salt_bytes = error_data[pos: pos + salt_len]
    if not salt_bytes:
        raise ValueError("Extracted salt is empty")

    salt = salt_bytes.decode('utf-8', errors='replace')
    return salt, etype


def nfold_for_kerberos():
    return b'\x6b\x65\x72\x62\x65\x72\x6f\x73\x7b\x9b\x5b\x2b\x93\x13\x2b\x93'


def aes_string_to_key(password: str, salt: str, key_len: int = 32):
    """
    Kerberos String-to-Key for AES (RFC 3962)
    key_len should be 16 for AES-128 or 32 for AES-256
    """
    tkey = PBKDF2(
        password,
        salt.encode(),
        dkLen=key_len,
        count=4096,
        hmac_hash_module=SHA1
    )

    constant = nfold_for_kerberos()

    # Kerberos DK (Random-to-Key) logic
    iv = b'\x00' * 16

    cipher1 = AES.new(tkey, AES.MODE_CBC, iv)
    part1 = cipher1.encrypt(constant)

    if key_len == 16:
        # For AES-128, the key is just the first 16-byte block
        return part1
    else:
        # For AES-256, we need a second 16-byte block
        cipher2 = AES.new(tkey, AES.MODE_CBC, iv)
        part2 = cipher2.encrypt(part1)
        return part1 + part2


async def get_tgt(username: str, password: str, domain: str,
                  kdc_host: str, kdc_port: int = 88) -> Tuple[bytes, bytes]:
    as_req = build_as_req(username, domain)
    resp = await send_kerberos_packet(as_req, kdc_host, kdc_port)
    parse_krb_error(resp)
    salt, etype = extract_salt_and_etype(resp)
    if etype != 18:
        raise ValueError('Only AES256 encryption supported for negotiation')
    base_key = aes_string_to_key(password, salt)
    full_as_req = build_full_as_req(username, domain, base_key, etype)
    as_res_bytes = await send_kerberos_packet(full_as_req, kdc_host, kdc_port)
    parse_krb_error(as_res_bytes)
    return as_res_bytes, base_key
