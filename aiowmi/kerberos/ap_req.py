from typing import Optional
from datetime import datetime, timezone
from .asn1 import asn1_len, asn1_tag, asn1_gt, asn1_int, asn1_ostr
from .tools import encrypt_kerberos_rc4, decrypt_kerberos_rc4
from .tools import decrypt_kerberos_aes_cts, encrypt_kerberos_aes_cts
from .const import OID_SPNEGO, OID_IETF_KRB5, OID_MS_KRB5


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

    # Read new session key...
    idx_a2 = auth_bytes.find(b'\xa2', etype_idx)
    idx_04 = auth_bytes.find(b'\x04', idx_a2)
    if idx_04 == -1:
        return None, 0

    pos = idx_04 + 1
    length_byte = auth_bytes[pos]
    pos += 1
    if length_byte & 0x80:
        n = length_byte & 0x7f
        length = int.from_bytes(auth_bytes[pos: pos + n], 'big')
        pos += n
    else:
        length = length_byte

    cipher_blob = auth_bytes[pos: pos + length]

    if etype == 0x17:
        decrypted_raw = \
            decrypt_kerberos_rc4(service_session_key, 12, cipher_blob)
        asn1_data = decrypted_raw[8:]  # Skip 8 bytes confounder
    elif etype in [0x11, 0x12]:
        decrypted_raw = \
            decrypt_kerberos_aes_cts(service_session_key, 12, cipher_blob)
        asn1_data = decrypted_raw[16:]  # Skip 16 bytes confounder

    if etype == 0x12:  # AES256
        KEY_MARKER = b'\x04\x20'
        k_len = 32
    else:  # AES128 / RC4
        KEY_MARKER = b'\x04\x10'
        k_len = 16

    key_idx = asn1_data.find(KEY_MARKER)
    if key_idx != -1:
        active_key = asn1_data[key_idx + 2: key_idx + 2 + k_len]

    SEQ_MARKER = b'\xa3'
    seq_idx = asn1_data.find(SEQ_MARKER)
    if seq_idx != -1:
        int_tag_idx = asn1_data.find(b'\x02', seq_idx)
        if int_tag_idx != -1 and int_tag_idx < seq_idx + 4:
            int_len = asn1_data[int_tag_idx + 1]
            offset = int_tag_idx + 2
            seq_bytes = asn1_data[offset: offset + int_len]
            seq_number = int.from_bytes(seq_bytes, 'big')

    return active_key, seq_number
