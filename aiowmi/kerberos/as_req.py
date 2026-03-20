import struct
import random
import hmac
import os
import hashlib
from datetime import datetime, timedelta, timezone
from .tools import aes_cts_encrypt, derive_key
from .asn1 import (
    asn1_len, asn1_seq, asn1_tag, asn1_int, asn1_gt, asn1_gs, asn1_ostr
)
from ..tools import get_random_bytes


def build_as_req(username: str, domain: str, pa_enc: bytes = b'') -> bytes:
    domain = domain.upper()

    # 0x01 0x01 0xff = Boolean True
    pac_req_inner = asn1_tag(0, b'\x01\x01\xff')
    pac_req = asn1_seq(pac_req_inner)

    # Type 128 (PA-PAC-REQUEST)
    padata_element_content = (
        asn1_tag(1, asn1_int(128)) +
        asn1_tag(2, asn1_ostr(pac_req))
    )
    padata_sequence_of = asn1_seq(pa_enc + asn1_seq(padata_element_content))

    # NT-PRINCIPAL = 1
    sname_components = (
        b'\x1b' + asn1_len(b'krbtgt') + b'krbtgt' +
        b'\x1b' + asn1_len(domain.encode()) + domain.encode()
    )
    sname = (
        asn1_tag(0, b'\x02\x01\x01') +
        asn1_tag(1,
                 b'\x30' +
                 struct.pack('B', len(sname_components)) +
                 sname_components)
    )

    # req-body: cname (user)
    cname_components = (
        b'\x1b' + asn1_len(username.encode()) + username.encode()
    )
    cname = (
        asn1_tag(0, asn1_int(1)) +  # NT-PRINCIPAL
        asn1_tag(1, asn1_seq(cname_components))
    )

    # KDC Body
    nonce = random.getrandbits(31)

    now = datetime.now(timezone.utc)

    # Start time: 5 minutes in the PAST to handle clock skew
    from_time = (now - timedelta(minutes=5)).strftime("%Y%m%d%H%M%SZ").encode()

    # End time: 10 hours is the standard Windows default
    till_time = (now + timedelta(hours=10)).strftime("%Y%m%d%H%M%SZ").encode()

    # Renewable time: 1 day (must be >= till)
    rtime_time = (now + timedelta(days=1)).strftime("%Y%m%d%H%M%SZ").encode()

    # Etype list: RC4 (23), AES128 (17), AES256 (18)
    etypes = asn1_int(18)

    # kdc-options: Forwardable, Proxiable, Renewable, Canonicalize
    kdc_options = b'\x03\x05\x00\x50\x80\x00\x00'
    req_body_fields = (
        asn1_tag(0, kdc_options) +
        asn1_tag(1, asn1_seq(cname)) +
        asn1_tag(2, b'\x1b' + asn1_len(domain.encode()) + domain.encode()) +
        asn1_tag(3, asn1_seq(sname)) +
        asn1_tag(4, asn1_gt(from_time)) +
        asn1_tag(5, asn1_gt(till_time)) +
        asn1_tag(6, asn1_gt(rtime_time)) +
        asn1_tag(7, asn1_int(nonce)) +
        asn1_tag(8, asn1_seq(etypes))
    )
    req_body_sequence = asn1_seq(req_body_fields)

    # AS_REQ
    as_req_fields = (
        asn1_tag(1, b'\x02\x01\x05') +  # pvno
        asn1_tag(2, b'\x02\x01\x0a') +  # msg-type
        asn1_tag(3, padata_sequence_of) +  # padata (Tag 3)
        asn1_tag(4, req_body_sequence)  # req-body (Tag 4)
    )
    inner_seq = asn1_seq(as_req_fields)

    # APPLICATION TAG 10 (0x6a)
    final_as_req = b'\x6a' + asn1_len(inner_seq) + inner_seq
    return final_as_req


def build_full_as_req(username: str, domain: str, base_key: bytes, etype: int):
    now = datetime.now(timezone.utc)
    micro = now.microsecond

    ts_str = now.strftime("%Y%m%d%H%M%SZ").encode()
    original_plain_body = (
        asn1_tag(0, asn1_gt(ts_str)) +       # [0] pausec (GeneralizedTime)
        asn1_tag(1, asn1_int(micro))         # [1] pusec (Microseconds)
    )
    original_plain = asn1_seq(original_plain_body)

    confounder = get_random_bytes(16)
    full_plain = confounder + original_plain

    ke = derive_key(base_key, 1, 0xAA)
    ki = derive_key(base_key, 1, 0x55)

    signature = hmac.new(ki, full_plain, hashlib.sha1).digest()[:12]
    cipher_only = aes_cts_encrypt(ke, full_plain)

    final_payload = cipher_only + signature

    enc_data_content = (
        asn1_tag(0, asn1_int(etype)) +      # etype 17 (AES128) or 18 (AES256)
        asn1_tag(2, asn1_ostr(final_payload))
    )

    enc_data = asn1_seq(enc_data_content)
    pa_ts_content = (
        asn1_tag(1, asn1_int(2)) +          # Type: PA-ENC-TIMESTAMP
        asn1_tag(2, asn1_ostr(enc_data))    # Value: Octet String
    )
    pa_ts = asn1_seq(pa_ts_content)

    pa_pac_val = asn1_seq(asn1_tag(0, b'\x01\x01\xff'))  # Boolean True
    pa_pac_content = (
        asn1_tag(1, asn1_int(128)) +
        asn1_tag(2, asn1_ostr(pa_pac_val))
    )
    pa_pac = asn1_seq(pa_pac_content)
    padata_field = asn1_tag(3, asn1_seq(pa_ts + pa_pac))

    # KDC-REQ-BODY
    domcaps = domain.upper()
    nonce = random.getrandbits(31)
    till = (now + timedelta(days=1)).strftime("%Y%m%d%H%M%SZ").encode()

    cname_content = (
        asn1_tag(0, asn1_int(1)) +
        asn1_tag(1, asn1_seq(asn1_gs(username.encode())))
    )
    sname_content = (
        asn1_tag(0, asn1_int(1)) +
        asn1_tag(1, asn1_seq(asn1_gs(b"krbtgt") + asn1_gs(domcaps.encode())))
    )

    # Etype list: RC4 (23), AES128 (17), AES256 (18)
    etypes = asn1_int(18)

    req_body_content = (
        asn1_tag(0, b'\x03\x05\x00\x50\x80\x00\x00') +  # kdc-options
        asn1_tag(1, asn1_seq(cname_content)) +
        asn1_tag(2, asn1_gs(domcaps.encode())) +
        asn1_tag(3, asn1_seq(sname_content)) +
        asn1_tag(5, asn1_gt(till)) +
        asn1_tag(6, asn1_gt(till)) +
        asn1_tag(7, asn1_int(nonce)) +
        asn1_tag(8, asn1_seq(etypes))
    )

    as_req_content = (
        asn1_tag(1, asn1_int(5)) +                      # pvno
        asn1_tag(2, asn1_int(10)) +                     # msg-type (AS-REQ)
        padata_field +
        asn1_tag(4, asn1_seq(req_body_content))         # req-body
    )

    inner_sequence = asn1_seq(as_req_content)
    final_as_req = b'\x6a' + asn1_len(inner_sequence) + inner_sequence
    return final_as_req
