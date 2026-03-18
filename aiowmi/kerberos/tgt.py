import hashlib
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Hash import SHA1
from .as_req import build_as_req, build_full_as_req
from .kdc import send_kerberos_packet
from .asn1 import get_asn1_len
from .tools import parse_krb_error


def extract_salt_and_etype(error_data: bytes) -> tuple[str, int]:
    if error_data[0] != 0x7e:
        raise ValueError("Invalid KRB-ERROR packet")

    e_data_idx = error_data.find(b'\xac')
    if e_data_idx == -1:
        raise ValueError("e-data (Tag 12) not found")

    salt_tag_idx = error_data.find(b'\x1b', e_data_idx)
    if salt_tag_idx == -1:
        # Default to no salt/empty string if not found
        salt = ""
    else:
        salt_len, salt_len_size = get_asn1_len(error_data, salt_tag_idx + 1)
        salt_start = salt_tag_idx + 1 + salt_len_size
        salt = error_data[salt_start: salt_start + salt_len].decode('utf-8')

    etype = 18  # Default to AES256 if we can't find it
    etype_search_start = error_data.find(
        b'\xa0',
        e_data_idx,
        salt_tag_idx if salt_tag_idx != -1 else None)

    if etype_search_start != -1:
        # The etype is an integer inside context tag 0xa0
        val_idx = error_data.find(b'\x02', etype_search_start)
        if val_idx != -1:
            e_len = error_data[val_idx + 1]
            offset = val_idx + 2
            etype = int.from_bytes(error_data[offset: offset + e_len], 'big')

    return salt, etype


def nfold_for_kerberos():
    return b'\x6b\x65\x72\x62\x65\x72\x6f\x73\x7b\x9b\x5b\x2b\x93\x13\x2b\x93'


def aes_string_to_key(password: str, salt: str, key_len: int = 32):
    """
    Kerberos String-to-Key for AES (RFC 3962)
    key_len should be 16 for AES-128 or 32 for AES-256
    """
    tkey = PBKDF2(
        password.encode(),
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
                  kdc_host: str, kdc_port: int = 88) -> tuple[bytes, bytes]:
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
