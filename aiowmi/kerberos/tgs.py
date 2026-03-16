import random
from Crypto.Cipher import AES
from datetime import datetime, timezone
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ, tag, namedtype, char
from .asn1 import (
    asn1_len, asn1_tag, asn1_seq, asn1_gs, asn1_ostr, asn1_int, asn1_gt
)
from .kdc import send_kerberos_packet
from .tools import decrypt_kerberos_aes_cts, encrypt_kerberos_aes_cts
from .tools import read_session_key, parse_krb_error
from .asn1 import get_asn1_len


def aes_cts_encrypt(key, plaintext):
    iv = b'\x00' * 16
    n = len(plaintext)

    if n % 16 == 0:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(plaintext)

    if n < 16:
        raise ValueError("Plaintext must be at least 16 bytes for AES-CTS")

    pad_len = 16 - (n % 16)
    padded_plain = plaintext + b'\x00' * pad_len

    cipher = AES.new(key, AES.MODE_CBC, iv)
    full_cipher = cipher.encrypt(padded_plain)

    last_block_start = (len(full_cipher) // 16 - 1) * 16
    prev_block_start = last_block_start - 16

    c_prev = full_cipher[prev_block_start:last_block_start]
    c_last = full_cipher[last_block_start:]

    return full_cipher[:prev_block_start] + c_last + c_prev[:n % 16]


class AS_REP(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 11)
    )

    componentType = namedtype.NamedTypes(
        namedtype.NamedType('pvno', univ.Integer().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatConstructed, 0))),
        namedtype.NamedType('msg-type', univ.Integer().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatConstructed, 1))),
        namedtype.OptionalNamedType(
            'padata',
            univ.SequenceOf(univ.Sequence()).subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatConstructed, 2))),
        namedtype.NamedType('crealm', char.GeneralString().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatConstructed, 3))),
        namedtype.NamedType('cname', univ.Any().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatConstructed, 4))),
        namedtype.NamedType('ticket', univ.Any().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatConstructed, 5))),
        namedtype.NamedType('enc-part', univ.Any().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatConstructed, 6)))
    )


class EncryptedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('etype', univ.Integer().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatConstructed, 0))),
        namedtype.OptionalNamedType('kvno', univ.Integer().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatConstructed, 1))),
        namedtype.NamedType('cipher', univ.OctetString().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatConstructed, 2)))
    )


def get_session_key(as_rep_bytes: bytes, base_key: bytes) -> bytes:
    as_rep_obj, _ = decoder.decode(as_rep_bytes, asn1Spec=AS_REP())

    enc_part_any = as_rep_obj['enc-part']
    enc_data_obj, _ = decoder.decode(
        bytes(enc_part_any),
        asn1Spec=EncryptedData()
    )

    cipher_blob = bytes(enc_data_obj['cipher'])

    decrypted = decrypt_kerberos_aes_cts(base_key, 3, cipher_blob)
    session_key = read_session_key(decrypted)

    return session_key


def build_tgs_req(username: str,
                  domain: str,
                  session_key: bytes,
                  ticket_bytes: bytes,
                  target_service: tuple[str, str]):
    now = datetime.now(timezone.utc)
    ts_str = now.strftime("%Y%m%d%H%M%SZ").encode()

    cname_content = (
        asn1_tag(0, asn1_int(1)) +
        asn1_tag(1, asn1_seq(asn1_gs(username.encode())))
    )

    domcaps = domain.upper()
    auth_body = (
        asn1_tag(0, asn1_int(5)) +                       # pvno
        asn1_tag(1, asn1_gs(domcaps.encode())) +         # crealm
        asn1_tag(2, asn1_seq(cname_content)) +           # cname
        asn1_tag(4, asn1_int(now.microsecond)) +         # cusec
        asn1_tag(5, asn1_gt(ts_str))                     # ctime
    )

    # Application Tag 2 (0x62) -> Authenticator
    auth_plain = b'\x62' + asn1_len(asn1_seq(auth_body)) + asn1_seq(auth_body)

    # Encrypt Authenticator (7 -> TGS-REQ) ---
    final_cipher = encrypt_kerberos_aes_cts(session_key, 7, auth_plain)
    auth_enc_seq = asn1_seq(
        asn1_tag(0, asn1_int(18)) +                      # etype AES256
        asn1_tag(2, asn1_ostr(final_cipher))               # cipher
    )

    # AP-REQ (-> PA-DATA)
    ap_req_body = (
        asn1_tag(0, asn1_int(5)) +                       # pvno
        asn1_tag(1, asn1_int(14)) +                      # msg-type (14=AP-REQ)
        asn1_tag(2, b'\x03\x05\x00\x00\x00\x00\x00') +   # ap-options
        asn1_tag(3, ticket_bytes) +                      # ticket
        asn1_tag(4, auth_enc_seq)                        # authenticator
    )
    ap_req_seq = asn1_seq(ap_req_body)
    encoded_ap_req = b'\x6e' + asn1_len(ap_req_seq) + ap_req_seq

    padata_item = asn1_seq(
        asn1_tag(1, asn1_int(1)) +                       # PA-TGS-REQ
        asn1_tag(2, asn1_ostr(encoded_ap_req))           # value
    )
    padata_field = asn1_tag(3, asn1_seq(padata_item))    # [3] padata

    service, host_fqdn = target_service
    sname_inner = (
        asn1_tag(0, asn1_int(2)) +                       # NT-SRV-INST
        asn1_tag(1, asn1_seq(
            asn1_gs(service.encode()) +
            asn1_gs(host_fqdn.encode())
        ))
    )

    # Etype list: RC4, AES128, DES, AES256
    etype_list = asn1_int(23) + asn1_int(16) + asn1_int(3) + asn1_int(18)
    nonce = random.getrandbits(31)

    req_body_content = (
        asn1_tag(0, b'\x03\x05\x00\x40\x81\x00\x10') +   # KDC Options
        asn1_tag(2, asn1_gs(domcaps.encode())) +         # Realm
        asn1_tag(3, asn1_seq(sname_inner)) +             # sname
        asn1_tag(5, asn1_gt(ts_str)) +                   # Till
        asn1_tag(7, asn1_int(nonce)) +                   # Nonce
        asn1_tag(8, asn1_seq(etype_list))                # Etypes
    )
    req_body_field = asn1_tag(4, asn1_seq(req_body_content))

    # TGS-REQ
    final_content = (
        asn1_tag(1, asn1_int(5)) +                       # pvno
        asn1_tag(2, asn1_int(12)) +                      # msg-type 12=TGS-REQ
        padata_field +
        req_body_field
    )

    # Application Tag 12 (0x6c) -> TGS-REQ
    inner_seq = asn1_seq(final_content)
    return b'\x6c' + asn1_len(inner_seq) + inner_seq


def extract_ticket(data):
    pos = 0
    if data[pos] not in [0x6b, 0x6d]:
        raise ValueError("Invalid Kerberos answer")

    _, len_size = get_asn1_len(data, pos + 1)
    pos += 1 + len_size  # AS-REP

    # Skip SEQUENCE tag (0x30)
    if data[pos] != 0x30:
        raise ValueError("SEQUENCE expected")
    _, len_size = get_asn1_len(data, pos + 1)
    pos += 1 + len_size

    while pos < len(data):
        tag = data[pos]
        content_len, len_size = get_asn1_len(data, pos + 1)

        if tag == 0xa5:
            ticket_start = pos + 1 + len_size
            tkt_len, tkt_len_size = get_asn1_len(data, ticket_start + 1)
            total_tkt_size = 1 + tkt_len_size + tkt_len
            return data[ticket_start: ticket_start + total_tkt_size]

        pos += 1 + len_size + content_len

    raise ValueError("Ticket tag [5] not found in sequence")


def get_service_key(resp_bytes: bytes,
                    session_key: bytes) -> tuple[bytes, bytes]:
    raw_obj, _ = decoder.decode(resp_bytes)
    enc_part = raw_obj.getComponentByPosition(5)

    cipher_blob = None
    for i in range(len(enc_part)):
        comp = enc_part.getComponentByPosition(i)
        if isinstance(comp, univ.OctetString):
            cipher_blob = bytes(comp)
            break

    if not cipher_blob:
        cipher_blob = bytes(enc_part[2])

    decrypted_raw = decrypt_kerberos_aes_cts(session_key, 8, cipher_blob)
    payload = decrypted_raw[16:]
    inner_obj, _ = decoder.decode(payload)

    key_sequence = inner_obj.getComponentByPosition(0)
    service_session_key = bytes(key_sequence.getComponentByPosition(1))

    ticket = raw_obj.getComponentByPosition(4)
    ticket_bytes = encoder.encode(ticket)

    WRAPPERS = [0xa3, 0xa4, 0xa5]

    if ticket_bytes[0] in WRAPPERS:
        try:
            ticket_start = ticket_bytes.index(b'\x61', 0, 10)
            ticket_bytes = ticket_bytes[ticket_start:]
        except ValueError:
            pass

    return ticket_bytes, service_session_key


async def get_tgs(username: str, domain: str, host: str,
                  as_rep_bytes: bytes, base_key: bytes,
                  kdc_host: str, kdc_port: int = 88) -> bytes:
    tgs_session_key = get_session_key(as_rep_bytes, base_key)
    tgs_ticket = extract_ticket(as_rep_bytes)
    tgs_req = build_tgs_req(username,
                            domain,
                            tgs_session_key,
                            tgs_ticket,
                            ("host", host))
    as_res_bytes = await send_kerberos_packet(tgs_req, kdc_host, kdc_port)
    parse_krb_error(as_res_bytes)
    ticket, service_key = get_service_key(as_res_bytes, tgs_session_key)
    return ticket, service_key
