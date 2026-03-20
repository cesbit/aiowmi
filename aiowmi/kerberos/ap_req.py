from typing import Optional, Tuple
from datetime import datetime, timezone
from .asn1 import get_asn1_len
from .asn1 import asn1_len, asn1_tag, asn1_gt, asn1_int, asn1_ostr
from .tools import encrypt_kerberos_rc4, decrypt_kerberos_rc4
from .tools import decrypt_kerberos_aes_cts, encrypt_kerberos_aes_cts
from .const import OID_SPNEGO, OID_IETF_KRB5, OID_MS_KRB5
from ..exceptions import NoNewActiveKey


def wrap_gss_kerberos(ap_req_bytes: bytes):
    outer_oid = OID_IETF_KRB5
    inner_oid = OID_MS_KRB5

    mech_types_inner = b'\x30' + asn1_len(outer_oid) + outer_oid
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


def _get_active_key(asn1_data: bytes) -> Tuple[Optional[bytes], Optional[int]]:
    n = len(asn1_data)
    p = 0

    while p < n:
        if asn1_data[p] in (0xa0, 0xa1, 0xa2, 0xa3):
            try:
                length, header_len = get_asn1_len(asn1_data, p + 1)
                if p + 1 + header_len + length <= n:
                    break
            except Exception:
                pass
        p += 1

    active_key = None
    seq_number = None

    while p < n:
        tag = asn1_data[p]
        length, header_len = get_asn1_len(asn1_data, p + 1)

        content_start = p + 1 + header_len
        content = asn1_data[content_start: content_start + length]

        if tag == 0xa2:
            work_data = content
            if len(content) > 0 and content[0] == 0x30:
                s_len, s_h = get_asn1_len(content, 1)
                work_data = content[1 + s_h: 1 + s_h + s_len]

            sp = 0
            while sp < len(work_data):
                st = work_data[sp]
                sl, sh = get_asn1_len(work_data, sp + 1)

                if st == 0xa1:
                    inner = work_data[sp + 1 + sh: sp + 1 + sh + sl]
                    if len(inner) > 0 and inner[0] == 0x04:
                        kl, kh = get_asn1_len(inner, 1)
                        active_key = inner[1 + kh: 1 + kh + kl]
                    break
                sp += 1 + sh + sl

        elif tag == 0xa3:
            if len(content) > 0 and content[0] == 0x02:
                il, ih = get_asn1_len(content, 1)
                seq_bytes = content[1+ih: 1+ih+il]
                seq_number = int.from_bytes(seq_bytes, 'big')
            else:
                seq_number = int.from_bytes(content, 'big')

        p = content_start + length

    return active_key, seq_number


def _extract_cipher_blob(auth_bytes: bytes, etype: int) -> Optional[bytes]:
    if auth_bytes.startswith(b'\xa1'):
        idx_a2 = auth_bytes.find(b'\xa2')
        if idx_a2 == -1:
            raise NoNewActiveKey()

        idx_04 = auth_bytes.find(b'\x04', idx_a2)
        if idx_04 == -1:
            raise NoNewActiveKey()

        length, header_len = get_asn1_len(auth_bytes, idx_04 + 1)
        start_pos = idx_04 + 1 + header_len
        kerberos_data = auth_bytes[start_pos: start_pos + length]
    else:
        kerberos_data = auth_bytes

    etype_marker = bytes([0x02, 0x01, etype])
    etype_idx = kerberos_data.find(etype_marker)
    if etype_idx == -1:
        return None

    idx_04_cipher = kerberos_data.find(b'\x04', etype_idx)
    if idx_04_cipher == -1:
        return None

    c_length, c_header_len = get_asn1_len(kerberos_data, idx_04_cipher + 1)
    c_start_pos = idx_04_cipher + 1 + c_header_len
    cipher_blob = kerberos_data[c_start_pos: c_start_pos + c_length]

    return cipher_blob


def get_active_key(auth_bytes: bytes,
                   service_session_key: bytes,
                   etype: int) -> Tuple[Optional[bytes], Optional[int]]:
    active_key, seq_number = None, None
    cipher_blob = _extract_cipher_blob(auth_bytes, etype)
    if cipher_blob is not None:

        if etype == 23:  # RC4
            cipher = decrypt_kerberos_rc4
            offset = 8  # Skip 8 bytes confounder
        elif etype in (17, 18):  # AES
            cipher = decrypt_kerberos_aes_cts
            offset = 16  # Skip 16 bytes confounder
        else:
            raise ValueError(f"Invalid E-type: {etype}")

        decrypted = cipher(service_session_key, 12, cipher_blob)
        asn1_data = decrypted[offset:]
        active_key, seq_number = _get_active_key(asn1_data)

    return active_key, seq_number
