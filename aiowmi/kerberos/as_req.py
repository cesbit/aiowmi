import struct
import random
import hmac
import os
import hashlib
from datetime import datetime, timedelta, timezone
from .tools import aes_cts_encrypt, derive_key
from .asn1 import asn1_len, asn1_seq, asn1_tag, krb_string


def build_as_req(username: str, domain: str, pa_enc: bytes = b'') -> bytes:
    domain = domain.upper()

    # 0x30 = Sequence, 0xA0 = Tag 0 (include-pac), 0x01 = Boolean, 0x01 = True
    pac_req = b'\x30\x05\xa0\x03\x01\x01\xff'

    # Type: 128 (PA-PAC-REQUEST)
    padata_element_content = (
        asn1_tag(1, b'\x02\x02\x00\x80') +  # Type 128
        asn1_tag(2, b'\x04\x07' + pac_req)  # Value
    )

    # Sequence: PA-DATA
    single_padata = (
        b'\x30' +
        struct.pack('B', len(padata_element_content)) +
        padata_element_content
    )

    combined = pa_enc + single_padata

    # SEQUENCE OF (Tag 0x30)
    padata_sequence_of = (
        b'\x30' +
        struct.pack('B', len(combined)) +
        combined
    )

    # NT-PRINCIPAL = 1
    sname_components = b'\x1b' + struct.pack('B', 6) + b'krbtgt' + \
                       b'\x1b' + struct.pack('B', len(domain)) + \
                       domain.encode()
    sname = (
        asn1_tag(0, b'\x02\x01\x01') +
        asn1_tag(1,
                 b'\x30' +
                 struct.pack('B', len(sname_components)) +
                 sname_components)
    )

    # req-body: cname (user)
    cname_components = (
        b'\x1b' +
        struct.pack('B', len(username)) +
        username.encode()
    )
    cname = (
        asn1_tag(0, b'\x02\x01\x01') +
        asn1_tag(1,
                 b'\x30' +
                 struct.pack('B', len(cname_components)) +
                 cname_components)
    )

    # KDC Body
    nonce = random.getrandbits(31)
    till = (
        datetime.now(timezone.utc) +
        timedelta(days=1)
    ).strftime("%Y%m%d%H%M%SZ").encode()

    # kdc-options: Forwardable, Proxiable, Renewable, Canonicalize
    kdc_options = b'\x03\x05\x00\x50\x80\x00\x00'
    # used to be b'\x03\x05\x00\x40\x81\x00\x10'

    req_body_fields = [

        asn1_tag(0, kdc_options),
        asn1_tag(1, b'\x30' + struct.pack('B', len(cname)) + cname),
        # realm
        asn1_tag(2, b'\x1b' + struct.pack('B', len(domain)) + domain.encode()),
        asn1_tag(3, b'\x30' + struct.pack('B', len(sname)) + sname),
        asn1_tag(5, b'\x18' + struct.pack('B', len(till)) + till),  # till
        asn1_tag(6, b'\x18' + struct.pack('B', len(till)) + till),  # rtime
        asn1_tag(7, b'\x02\x04' + struct.pack('>I', nonce)),
        # etype: aes256-cts-hmac-sha1-96 (18)
        asn1_tag(8, b'\x30\x03\x02\x01\x12')
    ]

    req_body_content = b''.join(req_body_fields)
    req_body_sequence = (
        b'\x30' +
        asn1_len(len(req_body_content)) +
        req_body_content
    )

    # --- AS-REQ ---
    as_req_fields = [
        asn1_tag(1, b'\x02\x01\x05'),  # pvno
        asn1_tag(2, b'\x02\x01\x0a'),  # msg-type
        asn1_tag(3, padata_sequence_of),  # padata (Tag 3)
        asn1_tag(4, req_body_sequence)  # req-body (Tag 4)
    ]

    as_req_content = b''.join(as_req_fields)
    inner_seq = (
        b'\x30' +
        asn1_len(len(as_req_content)) +
        as_req_content
    )

    # APPLICATION TAG 10 (0x6a)
    final_as_req = b'\x6a' + asn1_len(len(inner_seq)) + inner_seq

    return final_as_req


def build_full_as_req(username, domain, base_key):
    now = datetime.now(timezone.utc)
    ts_str = now.strftime("%Y%m%d%H%M%SZ").encode()
    original_plain = (
        b'\x30\x19' +
        b'\xa0\x11\x18\x0f' + ts_str +
        b'\xa1\x04\x02\x02\x00\x00'
    )

    confounder = os.urandom(16)
    full_plain = confounder + original_plain

    ke = derive_key(base_key, 1, 0xAA)
    ki = derive_key(base_key, 1, 0x55)
    signature = hmac.new(ki, full_plain, hashlib.sha1).digest()[:12]
    cipher_only = aes_cts_encrypt(ke, full_plain)

    final_payload = cipher_only + signature

    cipher_octet_string = (
        b'\x04' + asn1_len(len(final_payload)) + final_payload
    )

    enc_data_content = (
        asn1_tag(0, b'\x02\x01\x12') +
        asn1_tag(2, cipher_octet_string)
    )

    encodedEncryptedData = asn1_seq(enc_data_content)
    pa_ts_content = (
        asn1_tag(1, b'\x02\x01\x02') +
        b'\xa2' + asn1_len(len(encodedEncryptedData) + 2) +
        b'\x04' + asn1_len(len(encodedEncryptedData)) + encodedEncryptedData
    )
    pa_ts = asn1_seq(pa_ts_content)

    pa_pac_content = (
        asn1_tag(1, b'\x02\x02\x00\x80') +
        asn1_tag(2, b'\x04\x07\x30\x05\xa0\x03\x01\x01\xff')
    )
    pa_pac = asn1_seq(pa_pac_content)
    padata_sequence = asn1_seq(pa_ts + pa_pac)
    padata_field = asn1_tag(3, padata_sequence)

    # KDC-REQ-BODY
    domain_caps = domain.upper()
    nonce = random.getrandbits(31)
    till = (now + timedelta(days=1)).strftime("%Y%m%d%H%M%SZ").encode()

    cname_content = (
        asn1_tag(0, b'\x02\x01\x01') +
        asn1_tag(1, asn1_seq(krb_string(username)))
    )
    sname_content = (
        asn1_tag(0, b'\x02\x01\x01') +
        asn1_tag(1, asn1_seq(krb_string("krbtgt") + krb_string(domain_caps)))
    )

    req_body_content = (
        asn1_tag(0, b'\x03\x05\x00\x50\x80\x00\x00') +
        asn1_tag(1, asn1_seq(cname_content)) +
        asn1_tag(2, krb_string(domain_caps)) +
        asn1_tag(3, asn1_seq(sname_content)) +
        asn1_tag(5, b'\x18\x0f' + till) +
        asn1_tag(6, b'\x18\x0f' + till) +   # rtime
        asn1_tag(7, b'\x02\x04' + struct.pack('>I', nonce)) +
        asn1_tag(8, asn1_seq(b'\x02\x01\x12'))
    )
    req_body_field = asn1_tag(4, asn1_seq(req_body_content))
    as_req_content = (
        asn1_tag(1, b'\x02\x01\x05') +
        asn1_tag(2, b'\x02\x01\x0a') +
        padata_field +
        req_body_field
    )

    inner_sequence = asn1_seq(as_req_content)
    final_as_req = b'\x6a' + asn1_len(len(inner_sequence)) + inner_sequence
    return final_as_req
