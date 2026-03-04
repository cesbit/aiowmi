import os
import struct
from .asn1 import asn1_len, asn1_tag, asn1_seq
from .kdc import send_kerberos_packet
from .tools import derive_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.hmac import HMAC
from datetime import datetime, timezone
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ, tag, namedtype, char
from Cryptodome.Cipher import AES
from Cryptodome.Hash import HMAC, SHA1
import struct


def aes_cts_encrypt(key, plaintext):
    iv = b'\x00' * 16
    n = len(plaintext)

    if n % 16 == 0:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        return encryptor.update(plaintext) + encryptor.finalize()

    pad_len = 16 - (n % 16)
    padded_plain = plaintext + b'\x00' * pad_len

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    full_cipher = encryptor.update(padded_plain) + encryptor.finalize()

    last_block_start = (len(full_cipher) // 16 - 1) * 16
    prev_block_start = last_block_start - 16

    c_prev = full_cipher[prev_block_start:last_block_start]
    c_last = full_cipher[last_block_start:]

    return full_cipher[:prev_block_start] + c_last + c_prev[:n % 16]


def decrypt_kerberos_aes_cts(ciphertext, key):
    backend = default_backend()
    block_size = 16
    iv = b'\x00' * block_size

    if len(ciphertext) < block_size:
        raise ValueError("Ciphertext needs to be at least one block size")

    if len(ciphertext) % block_size == 0:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    n_blocks = (len(ciphertext) + block_size - 1) // block_size

    decrypted_prev = b''
    if n_blocks > 2:
        prev_blocks = ciphertext[:(n_blocks - 2) * block_size]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        decrypted_prev = decryptor.update(prev_blocks) + decryptor.finalize()
        iv = prev_blocks[-block_size:]

    cn_1 = ciphertext[
        (n_blocks - 2) * block_size:
        (n_blocks - 1) * block_size]
    cn = ciphertext[(n_blocks - 1) * block_size:]
    last_block_len = len(cn)

    cipher_ecb = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor_ecb = cipher_ecb.decryptor()
    dn_1 = decryptor_ecb.update(cn_1) + decryptor_ecb.finalize()

    stolen_bytes = dn_1[last_block_len:]
    cn_full = cn + stolen_bytes

    decryptor_ecb = cipher_ecb.decryptor()
    dn = decryptor_ecb.update(cn_full) + decryptor_ecb.finalize()

    pn_actual = bytes(a ^ b for a, b in zip(dn, iv))
    pn_1_actual = bytes(a ^ b for a, b in zip(dn_1[:last_block_len], cn))

    return decrypted_prev + pn_actual + pn_1_actual


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


def read_session_key(data: bytes) -> bytes:
    payload = data[16:]
    as_rep_part, _ = decoder.decode(payload)
    key_container_bytes = encoder.encode(as_rep_part[0])
    inner_key_seq, _ = decoder.decode(key_container_bytes)

    key_type_bytes = encoder.encode(inner_key_seq[0])
    key_value_bytes = encoder.encode(inner_key_seq[1])

    key_type_obj, _ = decoder.decode(key_type_bytes)
    key_value_obj, _ = decoder.decode(key_value_bytes)

    session_key = bytes(key_value_obj.asOctets())
    _key_type = int(key_type_obj)

    return session_key


def get_session_key(as_rep_bytes: bytes, base_key: bytes) -> bytes:
    as_rep_obj, _ = decoder.decode(as_rep_bytes, asn1Spec=AS_REP())

    enc_part_any = as_rep_obj['enc-part']
    enc_data_obj, _ = decoder.decode(
        bytes(enc_part_any),
        asn1Spec=EncryptedData()
    )

    cipher_bytes = bytes(enc_data_obj['cipher'])
    ciphertext = cipher_bytes[:-12]
    _hmac = cipher_bytes[-12:]

    ke = derive_key(base_key, 3, 0xAA)

    decrypted = decrypt_kerberos_aes_cts(ciphertext, ke)
    session_key = read_session_key(decrypted)

    return session_key


def krb_string(s):
    return b'\x1b' + asn1_len(len(s)) + s.encode()


def encrypt_authenticator(session_key_bytes, plain_text):
    usage = 7
    ki = derive_key(session_key_bytes, usage, 0x55)
    ke = derive_key(session_key_bytes, usage, 0xAA)

    confounder = os.urandom(16)
    basic_plaintext = confounder + plain_text

    h = HMAC.new(ki, basic_plaintext, SHA1)
    checksum = h.digest()[:12]

    aes = AES.new(ke, AES.MODE_CBC, b'\x00' * 16)
    pad_len = (16 - (len(basic_plaintext) % 16)) % 16
    padded_data = basic_plaintext + (b'\x00' * pad_len)
    ctext = aes.encrypt(padded_data)

    if len(basic_plaintext) > 16:
        lastlen = len(basic_plaintext) % 16 or 16
        final_ctext = ctext[:-32] + ctext[-16:] + ctext[-32:-16][:lastlen]
    else:
        final_ctext = ctext

    return final_ctext + checksum


def build_tgs_req(username: str,
                  domain: str,
                  session_key: bytes,
                  ticket_bytes: bytes,
                  target_service: tuple[str, str]):
    now = datetime.now(timezone.utc)
    ts_str = now.strftime("%Y%m%d%H%M%SZ").encode()

    cname_content = (
        asn1_tag(0, b'\x02\x01\x01') +
        asn1_tag(1, asn1_seq(krb_string(username)))
    )

    cusec_val = now.microsecond
    cusec_bytes = asn1_tag(4, b'\x02\x03' + struct.pack('>I', cusec_val)[1:])

    auth_body = (
        asn1_tag(0, b'\x02\x01\x05') +             # [0] pvno
        asn1_tag(1, krb_string(domain.upper())) +  # [1] crealm
        asn1_tag(2, asn1_seq(cname_content)) +     # [2] cname
        cusec_bytes +                              # [4] cusec (tag a4)
        asn1_tag(5, b'\x18\x0f' + ts_str)          # [5] ctime (tag a5)
    )

    inner_seq = b'\x30' + asn1_len(len(auth_body)) + auth_body
    auth_plain = b'\x62' + asn1_len(len(inner_seq)) + inner_seq
    final_cipher = encrypt_authenticator(session_key, auth_plain)
    etype_part = b'\xa0\x03\x02\x01\x12'  # [0] etype AES256

    cipher_octet = b'\x04' + asn1_len(len(final_cipher)) + final_cipher
    cipher_part = b'\xa2' + asn1_len(len(cipher_octet)) + cipher_octet

    auth_enc_seq = (
        b'\x30' +
        asn1_len(len(etype_part + cipher_part)) +
        etype_part +
        cipher_part
    )
    auth_field = b'\xa4' + asn1_len(len(auth_enc_seq)) + auth_enc_seq
    ap_req_body = (
        b'\xa0\x03\x02\x01\x05' +                          # [0] pvno
        b'\xa1\x03\x02\x01\x0e' +                          # [1] msg-type (14)
        b'\xa2\x07\x03\x05\x00\x00\x00\x00\x00' +          # [2] ap-options
        b'\xa3' + asn1_len(len(ticket_bytes)) + ticket_bytes +  # [3] ticket
        auth_field                                         # [4] authenticator
    )

    ap_req_sequence = b'\x30' + asn1_len(len(ap_req_body)) + ap_req_body
    encoded_ap_req = b'\x6e' + asn1_len(len(ap_req_sequence)) + ap_req_sequence
    padata_value = b'\x04' + asn1_len(len(encoded_ap_req)) + encoded_ap_req

    # padata-item (padata-type 1 = PA-TGS-REQ)
    padata_item_content = (
        b'\xa1\x03\x02\x01\x01' +  # [1] padata-type (PA-TGS-REQ)
        b'\xa2' + asn1_len(len(padata_value)) + padata_value
    )

    padata_item = (
        b'\x30' +
        asn1_len(len(padata_item_content)) +
        padata_item_content
    )
    padata_list_wrapper = b'\x30' + asn1_len(len(padata_item)) + padata_item
    padata_field = (
        b'\xa3' +
        asn1_len(len(padata_list_wrapper)) +
        padata_list_wrapper
    )

    service, host_fqdn = target_service
    sname_strings_seq = asn1_seq(krb_string(service) + krb_string(host_fqdn))
    sname_inner_content = (
        asn1_tag(0, b'\x02\x01\x02') +   # Name-type: 2
        asn1_tag(1, sname_strings_seq)   # strings
    )

    sname_field = (
        b'\xa3' +
        asn1_len(len(asn1_seq(sname_inner_content))) +
        asn1_seq(sname_inner_content)
    )
    etype_list = b'\x02\x01\x17\x02\x01\x10\x02\x01\x03\x02\x01\x12'
    fixed_nonce = 123456789

    req_body_content = (
        asn1_tag(0, b'\x03\x05\x00\x40\x81\x00\x10') +  # KDC Options
        asn1_tag(2, krb_string(domain.upper())) +       # Realm
        sname_field +                                   # [3] sname
        asn1_tag(5, b'\x18\x0f' + ts_str) +             # Till
        asn1_tag(7, b'\x02\x04' + struct.pack('>I', fixed_nonce)) +  # Nonce
        asn1_tag(8, asn1_seq(etype_list))               # Etypes
    )
    req_body_field = (
        b'\xa4' +
        asn1_len(len(asn1_seq(req_body_content))) +
        asn1_seq(req_body_content)
    )

    final_content = (
        b'\xa1\x03\x02\x01\x05' +                # [1] pvno
        b'\xa2\x03\x02\x01\x0c' +                # [2] msg-type (12 = TGS-REQ)
        padata_field +                           # [3] padata (a3...)
        req_body_field                           # [4] req-body (a4...)
    )

    inner_sequence = b'\x30' + asn1_len(len(final_content)) + final_content
    packet = b'\x6c' + asn1_len(len(inner_sequence)) + inner_sequence

    return packet


def extract_ticket_properly(as_rep_bytes):
    tag_5_idx = as_rep_bytes.find(b'\xa5')
    if tag_5_idx == -1:
        raise ValueError("Tag [5] (Ticket container) not found!")

    ticket_start = as_rep_bytes.find(b'\x61', tag_5_idx)
    len_bytes = as_rep_bytes[ticket_start + 2: ticket_start + 4]
    ticket_len = int.from_bytes(len_bytes, byteorder='big')
    total_len = ticket_len + 4
    ticket_payload = as_rep_bytes[ticket_start: ticket_start + total_len]

    return ticket_payload


async def get_tgs(username: str, domain: str, host: str,
                  as_rep_bytes: bytes, base_key: bytes,
                  kdc_host: str, kdc_port: int = 88) -> bytes:
    tgs_session_key = get_session_key(as_rep_bytes, base_key)
    ticket_bytes = extract_ticket_properly(as_rep_bytes)
    tgs_req = build_tgs_req(username,
                            domain,
                            tgs_session_key,
                            ticket_bytes,
                            ("host", host))
    as_res_bytes = await send_kerberos_packet(tgs_req, kdc_host, kdc_port)
    print(f"[+] TGS Sessoin key: {tgs_session_key.hex()}")
    print(f"[+] Response: {as_res_bytes.hex()}")

    assert 0
