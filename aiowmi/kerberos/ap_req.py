from datetime import datetime, timezone
from .asn1 import asn1_len, asn1_tag
from .tools import encrypt_kerberos_rc4
from .const import OID_KERBEROS_V5, OID_MS_LEGACY_KRB, OID_SPNEGO


def wrap_gss_kerberos(ap_req_bytes):
    # MechTypes [0]
    mech_types = asn1_tag(0, b'\x30\x0b' + OID_MS_LEGACY_KRB)

    # MechToken [2] -> GSS-API Token wrapper (0x60)
    inner_token = OID_KERBEROS_V5 + b'\x01\x00' + ap_req_bytes
    gss_token = b'\x60' + asn1_len(len(inner_token)) + inner_token

    # OctetString wrapper (0x04) MechToken [2]
    mech_token = asn1_tag(2, b'\x04' + asn1_len(len(gss_token)) + gss_token)

    # NegTokenInit Sequence [30] -> Wrapper [0]
    neg_token_body = mech_types + mech_token
    neg_token_seq = b'\x30' + asn1_len(len(neg_token_body)) + neg_token_body
    neg_token_init = asn1_tag(0, neg_token_seq)

    # Application 0 (0x60) wrapper
    final_body = OID_SPNEGO + neg_token_init
    return b'\x60' + asn1_len(len(final_body)) + final_body


def build_ap_req(username: str,
                 domain: str,
                 ticket: bytes,
                 service_session_key: bytes) -> bytes:
    now = datetime.now(timezone.utc)
    timestamp = now.strftime('%Y%m%d%H%M%SZ').encode('ascii')

    gss_data = b'\x10\x00\x00\x00' + b'\x00' * 16 + b'\x3e\x10\x00\x00'
    cksum_inner = (
        asn1_tag(0, b'\x02\x03\x00\x80\x03') +
        asn1_tag(1, b'\x04\x18' + gss_data)
    )
    cksum_asn1 = asn1_tag(3, b'\x30\x23' + cksum_inner)

    # CName [2]
    uname_bytes = b'\x1b' + asn1_len(len(username)) + username.encode()
    cname_inner = (
        asn1_tag(0, b'\x02\x01\x01') +
        asn1_tag(1, b'\x30' + asn1_len(len(uname_bytes)) + uname_bytes)
    )
    cname_asn1 = \
        asn1_tag(2, b'\x30' + asn1_len(len(cname_inner)) + cname_inner)

    # Realm [1]
    realm_asn1 = asn1_tag(1, b'\x1b' + asn1_len(len(domain)) + domain.encode())

    # Authenticator Body (Plaintext)
    auth_body = (
        asn1_tag(0, b'\x02\x01\x05') +
        realm_asn1 +
        cname_asn1 +
        cksum_asn1 +
        asn1_tag(4, b'\x02\x03\x03\x7b\xb7') +
        asn1_tag(5, b'\x18\x0f' + timestamp) +
        asn1_tag(7, b'\x02\x01\x00')
    )

    # Encrypt authenticator
    auth_inner = b'\x30' + asn1_len(len(auth_body)) + auth_body
    auth_asn1 = b'\x62' + asn1_len(len(auth_inner)) + auth_inner
    enc_auth = encrypt_kerberos_rc4(service_session_key, 11, auth_asn1)

    etype_asn1 = asn1_tag(0, b'\x02\x01\x17')  # RC4-HMAC (23)
    cipher_asn1 = asn1_tag(2, b'\x04' + asn1_len(len(enc_auth)) + enc_auth)
    enc_body = etype_asn1 + cipher_asn1
    enc_part = asn1_tag(4, b'\x30' + asn1_len(len(enc_body)) + enc_body)

    ap_req_body = (
        asn1_tag(0, b'\x02\x01\x05') +                  # pvno
        asn1_tag(1, b'\x02\x01\x0e') +                  # msg-type
        asn1_tag(2, b'\x03\x05\x00\x20\x00\x00\x00') +  # ap-options
        asn1_tag(3, ticket) +                           # ticket
        enc_part                                        # authenticator
    )

    inner_pdu = b'\x30' + asn1_len(len(ap_req_body)) + ap_req_body
    return b'\x6e' + asn1_len(len(inner_pdu)) + inner_pdu
