from datetime import datetime, timezone
from pyasn1.codec.ber import decoder, encoder
from .asn1 import asn1_len, asn1_tag, asn1_gt, asn1_int, asn1_ostr
from .tools import encrypt_kerberos_rc4, decrypt_kerberos_rc4
from .const import OID_KERBEROS_V5, OID_MS_LEGACY_KRB, OID_SPNEGO


def wrap_gss_kerberos(ap_req_bytes):
    # MechTypes [0]
    mech_types = asn1_tag(0, b'\x30\x0b' + OID_MS_LEGACY_KRB)

    # MechToken [2] -> GSS-API Token wrapper (0x60)
    inner_token = OID_KERBEROS_V5 + b'\x01\x00' + ap_req_bytes
    gss_token = b'\x60' + asn1_len(inner_token) + inner_token

    # OctetString wrapper (0x04) MechToken [2]
    mech_token = asn1_tag(2, asn1_ostr(gss_token))

    # NegTokenInit Sequence [30] -> Wrapper [0]
    neg_token_body = mech_types + mech_token
    neg_token_seq = b'\x30' + asn1_len(neg_token_body) + neg_token_body
    neg_token_init = asn1_tag(0, neg_token_seq)

    # Application 0 (0x60) wrapper
    final_body = OID_SPNEGO + neg_token_init
    return b'\x60' + asn1_len(final_body) + final_body


def build_ap_req(username: str,
                 domain: str,
                 ticket: bytes,
                 service_session_key: bytes) -> bytes:
    now = datetime.now(timezone.utc)
    timestamp = now.strftime('%Y%m%d%H%M%SZ').encode('ascii')

    gss_data = b'\x10\x00\x00\x00' + b'\x00' * 16 + b'\x3e\x10\x00\x00'
    cksum_inner = (
        asn1_tag(0, asn1_int(32771)) +
        asn1_tag(1, asn1_ostr(gss_data))
    )
    cksum_asn1 = asn1_tag(3, b'\x30\x23' + cksum_inner)

    # CName [2]
    uname_bytes = b'\x1b' + asn1_len(username) + username.encode()
    cname_inner = (
        asn1_tag(0, asn1_int(1)) +
        asn1_tag(1, b'\x30' + asn1_len(uname_bytes) + uname_bytes)
    )
    cname_asn1 = \
        asn1_tag(2, b'\x30' + asn1_len(cname_inner) + cname_inner)

    # Realm [1]
    realm_asn1 = asn1_tag(1, b'\x1b' + asn1_len(domain) + domain.encode())

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
    enc_auth = encrypt_kerberos_rc4(service_session_key, 11, auth_asn1)

    etype_asn1 = asn1_tag(0, b'\x02\x01\x17')  # RC4-HMAC (23)
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
                   service_session_key: bytes) -> tuple[bytes, int]:
    active_key, seq_number = None, 0

    if b'\x02\x01\x17' in auth_bytes:
        # Read new session key...
        etype_idx = auth_bytes.find(b'\x02\x01\x17')
        idx_a2 = auth_bytes.find(b'\xa2', etype_idx)
        idx_04 = auth_bytes.find(b'\x04', idx_a2)

        pos = idx_04 + 1
        length_byte = auth_bytes[pos]
        pos += 1
        if length_byte & 0x80:
            n = length_byte & 0x7f
            length = int.from_bytes(auth_bytes[pos : pos + n], 'big')
            pos += n
        else:
            length = length_byte

        cipher_blob = auth_bytes[pos : pos + length]

        decrypted_raw = \
            decrypt_kerberos_rc4(service_session_key, 12, cipher_blob)
        asn1_data = decrypted_raw[8:]  # Skip 8 bytes confounder

        KEY_MARKER = b'\xa1\x12\x04\x10'
        key_idx = asn1_data.find(KEY_MARKER)
        if key_idx != -1:
            active_key = asn1_data[key_idx + 4 : key_idx + 4 + 16]
            print('New activation key!', active_key)

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
