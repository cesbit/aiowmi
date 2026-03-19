from typing import Optional
from datetime import datetime, timezone
from .asn1 import asn1_len, asn1_tag, asn1_gt, asn1_int, asn1_ostr
from .tools import encrypt_kerberos_rc4, decrypt_kerberos_rc4
from .tools import decrypt_kerberos_aes_cts, encrypt_kerberos_aes_cts
from .const import OID_SPNEGO, OID_IETF_KRB5, OID_MS_KRB5
from ..exceptions import NoNewActiveKey


def wrap_gss_kerberos(ap_req_bytes: bytes, etype: int):
    if etype == 18:
        outer_oid = OID_IETF_KRB5
        inner_oid = OID_MS_KRB5
    elif etype == 17:
        outer_oid = OID_IETF_KRB5
        inner_oid = OID_MS_KRB5
    elif etype == 23:
        outer_oid = OID_MS_KRB5
        inner_oid = OID_MS_KRB5
    else:
        raise ValueError(f"Invalid E-type: {etype}")

    mech_types_inner = b'\x30\x0b' + outer_oid
    mech_types = asn1_tag(0, mech_types_inner)

    inner_gss_content = inner_oid + b'\x01\x00' + ap_req_bytes
    gss_wrapper = b'\x60' + asn1_len(inner_gss_content) + inner_gss_content

    mech_token = asn1_tag(2, asn1_ostr(gss_wrapper))

    neg_body = mech_types + mech_token
    neg_init = asn1_tag(0, b'\x30' + asn1_len(neg_body) + neg_body)

    final_payload = OID_SPNEGO + neg_init
    return b'\x60' + asn1_len(final_payload) + final_payload


def build_ap_req(username: str,
                 domain: str,
                 ticket: bytes,
                 service_session_key: bytes,
                 etype: int) -> bytes:
    now = datetime.now(timezone.utc)
    timestamp = now.strftime('%Y%m%d%H%M%SZ').encode('ascii')

    gss_data = b'\x10\x00\x00\x00' + b'\x00' * 16 + b'\x3e\x10\x00\x00'
    cksum_inner = (
        asn1_tag(0, asn1_int(32771)) +
        asn1_tag(1, asn1_ostr(gss_data))
    )
    cksum_asn1 = asn1_tag(3, b'\x30\x23' + cksum_inner)

    # CName [2]
    uname = username.encode()
    uname_bytes = b'\x1b' + asn1_len(uname) + uname
    cname_inner = (
        asn1_tag(0, asn1_int(1)) +
        asn1_tag(1, b'\x30' + asn1_len(uname_bytes) + uname_bytes)
    )
    cname_asn1 = \
        asn1_tag(2, b'\x30' + asn1_len(cname_inner) + cname_inner)

    # Realm [1]
    realm = domain.encode()
    realm_asn1 = asn1_tag(1, b'\x1b' + asn1_len(realm) + realm)

    # Authenticator Body (Plaintext)
    auth_body = (
        asn1_tag(0, asn1_int(5)) +
        realm_asn1 +
        cname_asn1 +
        cksum_asn1 +
        asn1_tag(4, asn1_int(now.microsecond)) +
        asn1_tag(5, asn1_gt(timestamp)) +
        asn1_tag(7, b'\x02\x01\x00')
    )

    # Encrypt authenticator
    auth_inner = b'\x30' + asn1_len(auth_body) + auth_body
    auth_asn1 = b'\x62' + asn1_len(auth_inner) + auth_inner

    if etype == 18:  # AES-256
        enc_auth = encrypt_kerberos_aes_cts(service_session_key, 11, auth_asn1)
        etype_byte = b'\x12'
    elif etype == 17:  # AES-128
        enc_auth = encrypt_kerberos_aes_cts(service_session_key, 11, auth_asn1)
        etype_byte = b'\x11'
    elif etype == 23:  # RC4
        enc_auth = encrypt_kerberos_rc4(service_session_key, 11, auth_asn1)
        etype_byte = b'\x17'
    else:
        raise ValueError(f"Invalid E-type: {etype}")

    etype_asn1 = asn1_tag(0, b'\x02\x01' + etype_byte)
    cipher_asn1 = asn1_tag(2, asn1_ostr(enc_auth))

    enc_body = etype_asn1 + cipher_asn1
    enc_part = asn1_tag(4, b'\x30' + asn1_len(enc_body) + enc_body)

    ap_req_body = (
        asn1_tag(0, asn1_int(5)) +                      # pvno
        asn1_tag(1, asn1_int(14)) +                     # msg-type
        asn1_tag(2, b'\x03\x05\x00\x20\x00\x00\x00') +  # ap-options
        asn1_tag(3, ticket) +                           # ticket
        enc_part                                        # authenticator
    )

    inner_pdu = b'\x30' + asn1_len(ap_req_body) + ap_req_body
    return b'\x6e' + asn1_len(inner_pdu) + inner_pdu


def get_active_key(auth_bytes: bytes,
                   service_session_key: bytes,
                   etype: int) -> tuple[Optional[bytes], int]:
    active_key, seq_number = None, 0

    etype_idx = auth_bytes.find(bytes([0x02, 0x01, etype]))
    if etype_idx == -1:
        return None, 0
    idx_04 = auth_bytes.find(b'\x04', etype_idx)
    if idx_04 == -1:
        return None, 0

    pos = idx_04 + 1
    lb = auth_bytes[pos]
    pos += 1
    if lb & 0x80:
        n = lb & 0x7f
        length = int.from_bytes(auth_bytes[pos: pos + n], 'big')
        pos += n
    else: length = lb
    cipher_blob = auth_bytes[pos: pos + length]

    if etype == 23:
        decrypted = \
            decrypt_kerberos_rc4(service_session_key, 12, cipher_blob)
        asn1_data = decrypted[8:]
    elif etype in [17, 18]:
        decrypted = \
            decrypt_kerberos_aes_cts(service_session_key, 12, cipher_blob)
        asn1_data = decrypted[16:]
    else:
        raise ValueError(f"Invalid E-type: {etype}")

    def get_tag_data(data: bytes, target_tag: int) -> Optional[bytes]:
        p = 0
        while p < len(data):
            tag = data[p]
            if tag == target_tag:
                try:
                    p += 1
                    lb = data[p]
                    p += 1
                    if lb & 0x80:
                        n_lb = lb & 0x7f
                        c_len = int.from_bytes(data[p: p+n_lb], 'big')
                        p += n_lb
                    else:
                        c_len = lb
                    return data[p : p + c_len]
                except:
                    return None
            p += 1
        return None

    subkey_cont = get_tag_data(asn1_data, 0xa2)
    if subkey_cont:
        key_seq = get_tag_data(subkey_cont, 0x30)
        if key_seq:
            key_val_wrapper = get_tag_data(key_seq, 0xa1)
            if key_val_wrapper:
                active_key = get_tag_data(key_val_wrapper, 0x04)

    seq_cont = get_tag_data(asn1_data, 0xa3)
    if seq_cont:
        seq_bytes = get_tag_data(seq_cont, 0x02)
        if seq_bytes:
            seq_number = int.from_bytes(seq_bytes, 'big')

    return active_key, seq_number

import struct
import binascii
from typing import Optional, Tuple

def get_active_key(auth_bytes: bytes,
                   service_session_key: bytes,
                   etype: int) -> Tuple[Optional[bytes], Optional[int]]:
    active_key, seq_number = None, None
    kerberos_data = auth_bytes

    if auth_bytes.startswith(b'\xa1'):
        idx_a2 = auth_bytes.find(b'\xa2')
        if idx_a2 == -1:
            raise NoNewActiveKey()

        idx_04 = auth_bytes.find(b'\x04', idx_a2)
        if idx_04 != -1:
            pos = idx_04 + 1
            lb = auth_bytes[pos]
            pos += 1
            if lb & 0x80:
                n = lb & 0x7f
                length = int.from_bytes(auth_bytes[pos:pos+n], 'big')
                pos += n
            else:
                length = lb
            kerberos_data = auth_bytes[pos: pos + length]
        else:
            raise NoNewActiveKey()

    etype_idx = kerberos_data.find(bytes([0x02, 0x01, etype]))
    if etype_idx == -1:
        return None, None

    idx_04_cipher = kerberos_data.find(b'\x04', etype_idx)
    if idx_04_cipher == -1:
        return None, None

    pos = idx_04_cipher + 1
    lb = kerberos_data[pos]
    pos += 1
    if lb & 0x80:
        n = lb & 0x7f
        c_length = int.from_bytes(kerberos_data[pos : pos + n], 'big')
        pos += n
    else:
        c_length = lb
    cipher_blob = kerberos_data[pos : pos + c_length]

    if etype == 23:  # RC4
        decrypted = \
            decrypt_kerberos_rc4(service_session_key, 12, cipher_blob)
        asn1_data = decrypted[8:]  # Skip 8 bytes confounder
    elif etype in [17, 18]:  # AES
        decrypted = \
            decrypt_kerberos_aes_cts(service_session_key, 12, cipher_blob)
        asn1_data = decrypted[16:]  # Skip 16 bytes confounder
    else:
        raise ValueError(f"Invalid E-type: {etype}")

    def peel_tag(data: bytes, target_tag: int):
        if not data:
            return None
        p = 0
        while p < len(data):
            tag = data[p]
            p += 1
            if p >= len(data):
                break
            lb = data[p]
            p += 1
            if lb & 0x80:
                n_lb = lb & 0x7f
                c_len = int.from_bytes(data[p: p+n_lb], 'big')
                p += n_lb
            else:
                c_len = lb
            if tag == target_tag:
                return data[p : p + c_len]
            p += c_len
        return None

    current = asn1_data
    if asn1_data.startswith(b'\x7b'):
        current = peel_tag(asn1_data, 0x7b)
        if current and current.startswith(b'\x30'):
            current = peel_tag(current, 0x30)

    subkey_cont = peel_tag(current, 0xa2)
    if subkey_cont:
        k_seq = peel_tag(subkey_cont, 0x30)
        if k_seq:
            k_val_wrap = peel_tag(k_seq, 0xa1)
            if k_val_wrap:
                active_key = peel_tag(k_val_wrap, 0x04)

    seq_cont = peel_tag(current, 0xa3)
    if seq_cont:
        inner_seq = peel_tag(seq_cont, 0x02)
        if inner_seq:
            seq_number = int.from_bytes(inner_seq, 'big')

    return active_key, seq_number