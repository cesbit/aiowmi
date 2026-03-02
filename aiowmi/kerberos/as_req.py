import struct
import random
import hmac
import os
import hashlib
from typing import Optional

from datetime import datetime, timedelta, timezone
from .tools import aes_cts_encrypt, derive_key, impacket_style_cts_encrypt


def asn1_tag(tag_num: int, content: bytes, is_context: bool = True):
    """ASN.1 DER tagger."""
    # Context-specific tags starting from 0xA0
    tag = (0xA0 + tag_num) if is_context else tag_num
    length = len(content)
    if length < 128:
        len_octet = struct.pack('B', length)
    else:
        len_bytes = length.to_bytes((length.bit_length() + 7) // 8, 'big')
        len_octet = struct.pack('B', 0x80 + len(len_bytes)) + len_bytes
    return struct.pack('B', tag) + len_octet + content


# def _encode_asn1_length(length: int) -> bytes:
#     if length < 128:
#         return struct.pack('B', length)
#     else:
#         b = length.to_bytes((length.bit_length() + 7) // 8, 'big')
#         return struct.pack('B', 0x80 + len(b)) + b

def _encode_asn1_length(length):
    if length <= 127:
        return struct.pack('B', length)
    else:
        # Long form: eerste byte is 0x80 + aantal lengte-bytes
        l_bytes = []
        temp_len = length
        while temp_len > 0:
            l_bytes.insert(0, temp_len & 0xFF)
            temp_len >>= 8
        return struct.pack('B', 0x80 | len(l_bytes)) + bytes(l_bytes)


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
        _encode_asn1_length(len(req_body_content)) +
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
        _encode_asn1_length(len(as_req_content)) +
        as_req_content
    )

    # APPLICATION TAG 10 (0x6a)
    final_as_req = b'\x6a' + _encode_asn1_length(len(inner_seq)) + inner_seq

    return final_as_req





def build_pa_enc_(base_key: bytes, kvno_val: int = 1):
    # Tijd moet op de seconde nauwkeurig zijn met de DC
    current_time_str = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%SZ")

    # 1. Sleutel Afleiding (Check lengtes)
    ke = derive_key(base_key, 1, 0xAA)
    ki = derive_key(base_key, 1, 0x55)
    assert len(ke) == 32, f"Ke moet 32 bytes zijn, kreeg {len(ke)}"
    assert len(ki) == 32, f"Ki moet 32 bytes zijn, kreeg {len(ki)}"

    # 2. Plaintext opbouw
    current_time_bytes = current_time_str.encode()
    # RFC 4120 PA-ENC-TS-ENC sequence
    plain = (
        b'\x30\x1a\xa0\x11\x18\x0f' +
        current_time_bytes +
        b'\xa1\x05\x02\x03\x00\x00\x00'
    )
    assert len(plain) == 28, f"Plaintext lengte mismatch: {len(plain)} != 28"

    # 3. Encryptie & Checksum
    # Bij AES-CTS MOET de ciphertext lengte gelijk zijn aan de plaintext lengte
    cipher_only = aes_cts_encrypt(ke, plain)
    assert len(cipher_only) == 28, f"AES-CTS fout: Ciphertext ({len(cipher_only)}) != Plaintext (28)"

    # HMAC-SHA1-96 (RFC 3962)
    signature = hmac.new(ki, cipher_only, hashlib.sha1).digest()
    checksum = signature[:12] # De '96' in de naam staat voor 96 bits = 12 bytes

    final_payload = cipher_only + checksum
    assert len(final_payload) == 40, f"Payload moet 40 bytes zijn (28+12), is {len(final_payload)}"

    # 4. ASN.1 EncryptedData Structuur
    # Gebruik kvno_val=1 als default, maar soms is 2 nodig voor Admin accounts
    enc_part_content = (
        asn1_tag(0, b'\x02\x01\x12') + # etype 18
        asn1_tag(1, b'\x02\x01' + struct.pack('B', kvno_val)) +
        asn1_tag(2, b'\x04' + _encode_asn1_length(len(final_payload)) + final_payload)
    )

    enc_data_seq = b'\x30' + _encode_asn1_length(len(enc_part_content)) + enc_part_content

    # Debug logging voor de structuur
    print(f"[D] EncryptedData Sequence lengte: {len(enc_data_seq)}")
    padata_type = b'\x02\x01\x02'  # Integer: 2 (PA-ENC-TIMESTAMP)

    # De waarde MOET een OCTET STRING zijn (0x04) die de encrypted_data_seq bevat
    padata_value = b'\x04' + _encode_asn1_length(len(enc_data_seq)) + enc_data_seq

    # Assembleer als een normale SEQUENCE (0x30)
    final_blob = b'\x30' + _encode_asn1_length(len(padata_type + padata_value)) + padata_type + padata_value

    print(f"[D] Totaal PA-ENC-TIMESTAMP lengte: {len(final_blob)} bytes")
    return final_blob


def _encode_asn1_length(n):
    """Binaire ASN.1 DER lengte encoding (geen ASCII!)"""
    if n <= 127:
        return struct.pack('B', n)
    else:
        # Long form voor lengtes > 127
        l_bytes = []
        temp = n
        while temp > 0:
            l_bytes.insert(0, temp & 0xFF)
            temp >>= 8
        return struct.pack('B', 0x80 | len(l_bytes)) + bytes(l_bytes)


def build_pa_enc(base_key: bytes):
    now = datetime.now(timezone.utc)
    ts_str = now.strftime("%Y%m%d%H%M%SZ").encode()

    # 1. Keys & Plaintext (Usage 1) - Dit was al goed
    ke = derive_key(base_key, 1, 0xAA)
    ki = derive_key(base_key, 1, 0x55)

    plain = b'\x30\x1c\xa0\x11\x18\x0f' + ts_str + b'\xa1\x05\x02\x03\x00\x00\x00'

    # 2. Encryptie - Dit was al goed
    cipher_only = aes_cts_encrypt(ke, plain)
    signature = hmac.new(ki, cipher_only, hashlib.sha1).digest()
    final_payload = cipher_only + signature[:12] # Totaal 40 bytes

    # 3. EncryptedData (VERANDERD: \x31 en \x2a)
    # \x30\x31 = Sequence van 49 bytes (5 etype + 2 tag2_header + 42 cipher_part)
    # \xa2\x2a = Tag [2] met lengte 42 (2 header + 40 payload)
    enc_data = b'\x30\x31\xa0\x03\x02\x01\x12\xa2\x2a\x04\x28' + final_payload

    # 4. PA-DATA wrapper (VERANDERD: \x3b en \x33 blijft)
    # De totale sequence is nu 59 bytes (\x3b) omdat enc_data langer is geworden
    # De Octet String (\x04\x33) bevat de 49 bytes van enc_data plus zijn eigen 2-byte header
    pa_enc_blob = b'\x30\x3b\x02\x01\x02\x04\x33' + enc_data

    return pa_enc_blob

import struct
import random
from datetime import datetime, timezone, timedelta

def build_full_as_req(username, domain, base_key):
    # --- HELPER FUNCTIES ---
    def asn1_len(n):
        if n <= 127: return struct.pack('B', n)
        l_bytes = []
        while n > 0:
            l_bytes.insert(0, n & 0xFF)
            n >>= 8
        return struct.pack('B', 0x80 | len(l_bytes)) + bytes(l_bytes)

    def asn1_tag(tag_num, content):
        return struct.pack('B', 0xa0 | tag_num) + asn1_len(len(content)) + content

    def asn1_seq(content):
        return b'\x30' + asn1_len(len(content)) + content

    print(f"[#] Building AS-REQ for {username}@{domain}")

    # --- 1. PRE-AUTH DATA (PA-ENC-TIMESTAMP) ---
    now = datetime.now(timezone.utc)
    ts_str = now.strftime("%Y%m%d%H%M%SZ").encode()
    print(f"[D] Timestamp: {ts_str.decode()}")

    pa_ts_enc = (
        b'\xa0\x11\x18\x0f' + ts_str +   # Tag [0] + Length 15 + Time
        b'\xa1\x03\x02\x01\x00'          # Tag [1] + Integer 0
    )
    original_plain = b'\x30\x18' + pa_ts_enc

    # Assertion: De ASN.1 timestamp sequence is bij AES256 meestal 20 bytes
    print(f"[D] ASN1 Plaintext len: {len(original_plain)} bytes")

    # 2. Confounder (16 willekeurige bytes)
    confounder = os.urandom(16)
    full_plain = confounder + original_plain
    print(f"[D] Total plaintext to encrypt (confounder + ASN1): {len(full_plain)} bytes")

    # 3. Key Derivation (Usage 1)
    ke = derive_key(base_key, 1, 0xAA)
    ki = derive_key(base_key, 1, 0x55)
    assert len(ke) == 32, "Encryption key must be 32 bytes for AES-256"
    assert len(ki) == 32, "Integrity key must be 32 bytes for AES-256"

    # 4. Checksum (HMAC-SHA1 over de VOLLEDIGE plaintext)
    signature = hmac.new(ki, full_plain, hashlib.sha1).digest()[:12]
    assert len(signature) == 12, "Kerberos AES HMAC must be truncated to 12 bytes"

    # 5. Encryptie (AES-CTS over de VOLLEDIGE plaintext)
    cipher_only = aes_cts_encrypt(ke, full_plain)

    # Assertion: Bij CTS moet de ciphertext EXACT even lang zijn als de plaintext
    assert len(cipher_only) == len(full_plain), f"CTS Error: Cipher ({len(cipher_only)}) != Plain ({len(full_plain)})"

    # 6. De uiteindelijke PA-DATA waarde
    final_payload = cipher_only + signature

    # CRUCIALE ASSERTION:
    # Voor een standaard timestamp (20 bytes) + confounder (16 bytes) + HMAC (12 bytes) = 48 bytes.
    # Als dit faalt, accepteert de Windows KDC het pakket sowieso niet.
    assert len(final_payload) == len(full_plain) + 12, f"Payload length mismatch: {len(final_payload)}"
    print(f"[D] Final PA-DATA payload: {len(final_payload)} bytes (Success)")

    # --- ASN.1 Packaging van PA-DATA ---
    # enc_data_content = asn1_tag(0, b'\x02\x01\x12') + asn1_tag(2, b'\x04' + asn1_len(len(final_payload)) + final_payload)
    # encodedEncryptedData = asn1_seq(enc_data_content)

    # pa_ts_content = asn1_tag(1, b'\x02\x01\x02') + asn1_tag(2, b'\x04' + asn1_len(len(encodedEncryptedData)) + encodedEncryptedData)

    cipher_octet_string = b'\x04' + asn1_len(len(final_payload)) + final_payload

    # 3. Maak de EncryptedData content
    # Tag [0] is etype, Tag [2] is de cipher (verpakt als Octet String!)
    enc_data_content = (
        asn1_tag(0, b'\x02\x01\x12') +
        asn1_tag(2, cipher_octet_string)
    )

    # 4. Maak de Sequence
    encodedEncryptedData = asn1_seq(enc_data_content)

    # 2. Bouw de PA-DATA (padata-type [1] en padata-value [2])
    # De padata-value MOET een Octet String zijn die de encoded sequence bevat
    pa_ts_content = (
        asn1_tag(1, b'\x02\x01\x02') +
        b'\xa2' + asn1_len(len(encodedEncryptedData) + 2) + # Tag [2]
        b'\x04' + asn1_len(len(encodedEncryptedData)) + encodedEncryptedData # De Octet String wrapper
    )
    pa_ts = asn1_seq(pa_ts_content)

    # B. PA-PAC-REQUEST
    pa_pac_content = asn1_tag(1, b'\x02\x02\x00\x80') + asn1_tag(2, b'\x04\x07\x30\x05\xa0\x03\x01\x01\xff')
    pa_pac = asn1_seq(pa_pac_content)

    padata_sequence = asn1_seq(pa_ts + pa_pac)
    padata_field = asn1_tag(3, padata_sequence)

    # --- 2. KDC-REQ-BODY (Tag [4]) ---
    domain_caps = domain.upper()
    nonce = random.getrandbits(31)
    till = (now + timedelta(days=1)).strftime("%Y%m%d%H%M%SZ").encode()

    def krb_string(s):
        return b'\x1b' + asn1_len(len(s)) + s.encode()

    cname_content = asn1_tag(0, b'\x02\x01\x01') + asn1_tag(1, asn1_seq(krb_string(username)))
    sname_content = asn1_tag(0, b'\x02\x01\x01') + asn1_tag(1, asn1_seq(krb_string("krbtgt") + krb_string(domain_caps)))

    req_body_content = (
        asn1_tag(0, b'\x03\x05\x00\x50\x80\x00\x00') +
        asn1_tag(1, asn1_seq(cname_content)) +
        asn1_tag(2, krb_string(domain_caps)) +
        asn1_tag(3, asn1_seq(sname_content)) +
        asn1_tag(5, b'\x18\x0f' + till) +
        asn1_tag(7, b'\x02\x04' + struct.pack('>I', nonce)) +
        asn1_tag(8, asn1_seq(b'\x02\x01\x12\x02\x01\x11'))
    )
    req_body_field = asn1_tag(4, asn1_seq(req_body_content))

    # --- 3. FINAL AS-REQ ASSEMBLY ---
    as_req_content = (
        asn1_tag(1, b'\x02\x01\x05') +
        asn1_tag(2, b'\x02\x01\x0a') +
        padata_field +
        req_body_field
    )

    inner_sequence = asn1_seq(as_req_content)
    final_as_req = b'\x6a' + asn1_len(len(inner_sequence)) + inner_sequence

    print(f"[#] AS-REQ built successfully. Total size: {len(final_as_req)} bytes")
    return final_as_req