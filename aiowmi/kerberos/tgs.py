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
        raise ValueError("Ciphertext moet minimaal één blok lang zijn")

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

    cn_1 = ciphertext[(n_blocks - 2) * block_size : (n_blocks - 1) * block_size]
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
        namedtype.OptionalNamedType('padata',
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
        # Gebruik explicitTag omdat de bytes 'a0', 'a1', 'a2' laten zien (Constructed)
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


def read_session_key(data: bytes) -> tuple[bytes, int]:
    payload = data[16:]
    print(f"[*] Payload start: {payload[0:1].hex()}")

    as_rep_part, _ = decoder.decode(payload)

    key_container_bytes = encoder.encode(as_rep_part[0])

    inner_key_seq, _ = decoder.decode(key_container_bytes)

    key_type_bytes = encoder.encode(inner_key_seq[0])
    key_value_bytes = encoder.encode(inner_key_seq[1])

    key_type_obj, _ = decoder.decode(key_type_bytes)
    key_value_obj, _ = decoder.decode(key_value_bytes)

    session_key = bytes(key_value_obj.asOctets())
    key_type = int(key_type_obj)

    return session_key, key_type


def get_session_key(as_rep_bytes, base_key):
    as_rep_obj, _ = decoder.decode(as_rep_bytes, asn1Spec=AS_REP())

    enc_part_any = as_rep_obj['enc-part']
    enc_data_obj, _ = decoder.decode(
        bytes(enc_part_any),
        asn1Spec=EncryptedData()
    )

    cipher_bytes = bytes(enc_data_obj['cipher'])
    ciphertext = cipher_bytes[:-12]
    # _hmac = cipher_bytes[-12:]

    ke = derive_key(base_key, 3, 0xAA)

    decrypted = decrypt_kerberos_aes_cts(ciphertext, ke)
    session_key, key_type = read_session_key(decrypted)

    print(f"[!] SUCCESS! Session Key: {session_key.hex()}")
    return session_key, key_type


def krb_string(s):
    return b'\x1b' + asn1_len(len(s)) + s.encode()



def encrypt_authenticator(session_key_bytes, plain_text):
    usage = 7
    # Impacket deriveert Ki/Ke met deze specifieke constant-opbouw:
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


def build_tgs_req(username, domain, session_key, key_type, ticket_bytes, target_service):
    print("\n--- START TGS-REQ DEBUG ---")
    now = datetime.now(timezone.utc)
    ts_str = now.strftime("%Y%m%d%H%M%SZ").encode()

    cname_content = (
        asn1_tag(0, b'\x02\x01\x01') +
        asn1_tag(1, asn1_seq(krb_string(username)))
    )
    auth_body = (
        asn1_tag(0, b'\x02\x01\x05') +            # [0] pvno
        asn1_tag(1, krb_string(domain.upper())) + # [1] crealm
        asn1_tag(2, asn1_seq(cname_content)) +    # [2] cname
        asn1_tag(4, b'\x02\x01\x00') +
        asn1_tag(5, b'\x18\x0f' + ts_str)
    )
    auth_plain = b'\x30' + asn1_len(len(auth_body)) + auth_body
    final_cipher = encrypt_authenticator(session_key, auth_plain)

    print(f"[D] Authenticator Plain: {len(auth_plain)} bytes")
    print(f"[D] Final Ciphertext (incl signature): {len(final_cipher)} bytes")
    etype_part = b'\xa0\x03\x02\x01\x12' # AES256
    cipher_part = b'\xa2' + asn1_len(len(final_cipher)) + final_cipher
    auth_enc_seq = b'\x30' + asn1_len(len(etype_part + cipher_part)) + etype_part + cipher_part
    auth_field = b'\xa4' + asn1_len(len(auth_enc_seq)) + auth_enc_seq
    ap_req_body = (
        b'\xa0\x03\x02\x01\x05' +                          # pvno [0]
        b'\xa1\x03\x02\x01\x0e' +                          # msg-type [1]
        b'\xa2\x07\x03\x05\x00\x00\x00\x00\x00' +          # ap-options [2]
        b'\xa3' + asn1_len(len(ticket_bytes)) + ticket_bytes + # ticket [3]
        auth_field                                         # authenticator [4]
    )
    ap_req_sequence = b'\x30' + asn1_len(len(ap_req_body)) + ap_req_body
    encoded_ap_req = b'\x6e' + asn1_len(len(ap_req_sequence)) + ap_req_sequence
    print(f"[D] my lib auth_field HEX: {auth_field.hex()}")
    print('#'*200)
    print(f"[D] AP-REQ Payload Len: {len(ap_req_sequence)} {ap_req_sequence.hex()}") # Moet 1492 zijn
    print(f"[D] AP-REQ Totaal Len:  {len(encoded_ap_req)}")  # Moet 1496 zijn
    print('-'*100)
    print(f'[D] AP_REQ_AUTHENTICATOR: a48180307ea003020112a27704753965a96bbab3515318d5272b80c608136d3721d4df6f62f5f55006090051a7d8fceaa06e96fd71ef9afb2778a3fb28a1c42d2f083e3e8b0a284f0d77b1d8bf7a4678136936a1bb80b6571b9e41729fa338c4c9f1147b3f5e7a84591380e3e452162b1cfb7aec49922fa6480b3b6253af20fe1e0518')
    print(f'[D] AP_REQ IMPACKET: 6e8205d4308205d0a003020105a10302010ea20703050000000000a3820536618205323082052ea003020105a1181b164c41422e544553542d544543484e4f4c4f47592e4e4ca22b3029a003020101a12230201b066b72627467741b164c41422e544553542d544543484e4f4c4f47592e4e4ca38204de308204daa003020112a103020102a28204cc048204c884011aa7c69b09f4d6680981400e95cbfebef52510d3f8850132af89ad9e4377240ca133de8c554b94107f599a0cd88481f52a7165bac944bbe71fb82c4f6050de8889e57d789ccbb2e9162860af913cb2c2f4ed05d86740998133e3ead98c8ef3017b534cd9f37e34c6347537e5db2ce07fd6663e75cd9eaa5de2e1a227a301afb17b38912386d4e5f00800864de0ee8c142a5aae9886d6d0b99d0001a55ccd77a091f5df3e3d57ac1cec4e51ddfee1f77dec14dd9ba22e321cdcb754938d0f33446083c6dd4c62b21064d3fcaed54a2146596df212bdb081f37ded0677caa6983e2243a57a3d85e26a9e784011271a8088a42c1ee8bb7243eb1bf7c125ad587017a333fceafb2962a2b3045a28f07f20404061126ec47960fa838ee5a1869997ea272ddfe88e28a639cec7a3b7abd2d9a6193a7a4e705f498f334a489ebec6d790564b29372b13ae922afab6d2e328cf402c7e257639ad250b0a19799140e5674c490ebb579bf07029477433fa1eaefa7687aec05ee6c940397117ef89df1fb10cc9c7fdb7feaa29abf0c45228da38ccb6338ddb62cc6ea5d853b4c253bcc3caaf9e78a356b2c657692200bcfb6fb9191ed8ff1479bca0a1882b166d45f6cba4d73ce8823758d3396d1be77363f9dc8057580e0df6ec7deef2de6e94a77d49a123c3c51ca6cb941c745028a4ecd2d3892d7321cb97cfeef1ea0abb365beeada605f83b49247b360f38e6a58fb8dea6ef3ad1e7edb5338ba4e1aa3b538cb3765d25e342b3498b3d5c622bc26571869d5bc696061ec1417f8793e1d917bd2da8da73deb853919f69ec7274ed6d84c84234447e7f2443ab872d58c8ad3d65465ff7a48e765a0d99685e0e908efe374f04044d84076928bd938a83a32e0a551bd45242676d86f19048f2e1bcd4b0d334189bb5a136f457666694c576b1e5bbab5291f15d4276721979e981a523c5cb187286eb1dddbbe81340a5f1c47585d3386ccd9c71dec1c2470b613146cd6f9a0974822237c7fd9b64a5f2f7e00e74e65356268b49428f00b1cbdde8518c236f3d895cdbf112162e50ec33626af1a85aec4412eb8f25112f1ade23b301cc1ae8c4183245ed3a7810a51563a0282125a4fa9b080cb96b95430fae51faf28028d75d226bbd04f20329b3e80f9e95f3bc903eaecf43b025ae213c88c5fdd3cf16b36ab746c325493c3906770411b5248028a0d537392c0cb9a5ceaba3b6fe8ed4fe8cdcbcdd87341c90df29645596c9a0d19ecb077d56ee188baaae7a226b4af896d8684ee0ed7a5f89a8c12ed98fcee60fd9bfaa4c925fa29f8e9bdc7d1bbd2ffba956c926fbb1c1affc37fba0dbed2d30afbd164d29719d6af3e5f3ab97706966bfe29b8f951bbde6295f84e6ef50cba6f1385492bf4dfe6d41e09ccb6a49fe0685a8190b9ed35c61cc9f0fb5f1f7f09b1dcfd93b45593b3f3b32133bfe834c9805664a43c6ebf5f64d7bdb54cfe51e1ff350413dab765d79ffe1dfc70c051e948ced919db9a0994d8add0fbce839f29d2ac0bc4c4e628f1127581db02125b5856fa572acfb763dd5723d0b9f31f79e01550177ee7376e1233eca8f12e1521976f39acf186b3c24b06cc92dcc179933c7b61d4681c79dcbc16d42257b0efb742d3435ff0359e2b78eba7ce4dd52e7eab8b1a6824d4138ecbdcfbe6f03b71fe013025e0e5d95f0ebdc2cd54ebda39fa3cd93261a8cd1586e7f3a76a48180307ea003020112a27704753965a96bbab3515318d5272b80c608136d3721d4df6f62f5f55006090051a7d8fceaa06e96fd71ef9afb2778a3fb28a1c42d2f083e3e8b0a284f0d77b1d8bf7a4678136936a1bb80b6571b9e41729fa338c4c9f1147b3f5e7a84591380e3e452162b1cfb7aec49922fa6480b3b6253af20fe1e0518')
    print('-'*100)

    padata_value_octet = b'\x04' + asn1_len(len(encoded_ap_req)) + encoded_ap_req
    padata_item_content = (
        asn1_tag(1, b'\x02\x01\x01') +      # padata-type [1]
        asn1_tag(2, padata_value_octet)     # padata-value [2]
    )
    padata_item = b'\x30' + asn1_len(len(padata_item_content)) + padata_item_content
    padata_list_wrapper = b'\x30' + asn1_len(len(padata_item)) + padata_item
    padata_field = b'\xa3' + asn1_len(len(padata_list_wrapper)) + padata_list_wrapper

    print(f"[D] Ticket Bytes Len: {len(ticket_bytes)}")
    print(f"[D] Auth Field Len:   {len(auth_field)} HEX: {auth_field.hex()}")
    print(f"[D] AP-REQ Totaal:    {len(encoded_ap_req)} bytes")
    print(f"[D] PADATA field len: {len(padata_field)} bytes")

    host_fqdn = target_service[1]
    sname_strings_seq = asn1_seq(krb_string("host") + krb_string(host_fqdn))
    sname_inner_content = (
        asn1_tag(0, b'\x02\x01\x02') +   # Name-type: 2
        asn1_tag(1, sname_strings_seq)   # strings
    )

    sname_field = b'\xa3' + asn1_len(len(asn1_seq(sname_inner_content))) + asn1_seq(sname_inner_content)
    etype_list = b'\x02\x01\x17\x02\x01\x10\x02\x01\x03\x02\x01\x12'
    fixed_nonce = 123456789

    req_body_content = (
        asn1_tag(0, b'\x03\x05\x00\x40\x81\x00\x10') + # KDC Options
        asn1_tag(2, krb_string(domain.upper())) +      # Realm
        sname_field +                                  # [3] sname
        asn1_tag(5, b'\x18\x0f' + ts_str) +            # Till
        asn1_tag(7, b'\x02\x04' + struct.pack('>I', fixed_nonce)) + # Nonce
        asn1_tag(8, asn1_seq(etype_list))              # Etypes
    )
    req_body_field = b'\xa4' + asn1_len(len(asn1_seq(req_body_content))) + asn1_seq(req_body_content)

    print(f'[D] AP_REQ IMPACKET: 6e8205d4308205d0a003020105a10302010ea20703050000000000a3820536618205323082052ea003020105a1181b164c41422e544553542d544543484e4f4c4f47592e4e4ca22b3029a003020101a12230201b066b72627467741b164c41422e544553542d544543484e4f4c4f47592e4e4ca38204de308204daa003020112a103020102a28204cc048204c884011aa7c69b09f4d6680981400e95cbfebef52510d3f8850132af89ad9e4377240ca133de8c554b94107f599a0cd88481f52a7165bac944bbe71fb82c4f6050de8889e57d789ccbb2e9162860af913cb2c2f4ed05d86740998133e3ead98c8ef3017b534cd9f37e34c6347537e5db2ce07fd6663e75cd9eaa5de2e1a227a301afb17b38912386d4e5f00800864de0ee8c142a5aae9886d6d0b99d0001a55ccd77a091f5df3e3d57ac1cec4e51ddfee1f77dec14dd9ba22e321cdcb754938d0f33446083c6dd4c62b21064d3fcaed54a2146596df212bdb081f37ded0677caa6983e2243a57a3d85e26a9e784011271a8088a42c1ee8bb7243eb1bf7c125ad587017a333fceafb2962a2b3045a28f07f20404061126ec47960fa838ee5a1869997ea272ddfe88e28a639cec7a3b7abd2d9a6193a7a4e705f498f334a489ebec6d790564b29372b13ae922afab6d2e328cf402c7e257639ad250b0a19799140e5674c490ebb579bf07029477433fa1eaefa7687aec05ee6c940397117ef89df1fb10cc9c7fdb7feaa29abf0c45228da38ccb6338ddb62cc6ea5d853b4c253bcc3caaf9e78a356b2c657692200bcfb6fb9191ed8ff1479bca0a1882b166d45f6cba4d73ce8823758d3396d1be77363f9dc8057580e0df6ec7deef2de6e94a77d49a123c3c51ca6cb941c745028a4ecd2d3892d7321cb97cfeef1ea0abb365beeada605f83b49247b360f38e6a58fb8dea6ef3ad1e7edb5338ba4e1aa3b538cb3765d25e342b3498b3d5c622bc26571869d5bc696061ec1417f8793e1d917bd2da8da73deb853919f69ec7274ed6d84c84234447e7f2443ab872d58c8ad3d65465ff7a48e765a0d99685e0e908efe374f04044d84076928bd938a83a32e0a551bd45242676d86f19048f2e1bcd4b0d334189bb5a136f457666694c576b1e5bbab5291f15d4276721979e981a523c5cb187286eb1dddbbe81340a5f1c47585d3386ccd9c71dec1c2470b613146cd6f9a0974822237c7fd9b64a5f2f7e00e74e65356268b49428f00b1cbdde8518c236f3d895cdbf112162e50ec33626af1a85aec4412eb8f25112f1ade23b301cc1ae8c4183245ed3a7810a51563a0282125a4fa9b080cb96b95430fae51faf28028d75d226bbd04f20329b3e80f9e95f3bc903eaecf43b025ae213c88c5fdd3cf16b36ab746c325493c3906770411b5248028a0d537392c0cb9a5ceaba3b6fe8ed4fe8cdcbcdd87341c90df29645596c9a0d19ecb077d56ee188baaae7a226b4af896d8684ee0ed7a5f89a8c12ed98fcee60fd9bfaa4c925fa29f8e9bdc7d1bbd2ffba956c926fbb1c1affc37fba0dbed2d30afbd164d29719d6af3e5f3ab97706966bfe29b8f951bbde6295f84e6ef50cba6f1385492bf4dfe6d41e09ccb6a49fe0685a8190b9ed35c61cc9f0fb5f1f7f09b1dcfd93b45593b3f3b32133bfe834c9805664a43c6ebf5f64d7bdb54cfe51e1ff350413dab765d79ffe1dfc70c051e948ced919db9a0994d8add0fbce839f29d2ac0bc4c4e628f1127581db02125b5856fa572acfb763dd5723d0b9f31f79e01550177ee7376e1233eca8f12e1521976f39acf186b3c24b06cc92dcc179933c7b61d4681c79dcbc16d42257b0efb742d3435ff0359e2b78eba7ce4dd52e7eab8b1a6824d4138ecbdcfbe6f03b71fe013025e0e5d95f0ebdc2cd54ebda39fa3cd93261a8cd1586e7f3a76a48180307ea003020112a27704753965a96bbab3515318d5272b80c608136d3721d4df6f62f5f55006090051a7d8fceaa06e96fd71ef9afb2778a3fb28a1c42d2f083e3e8b0a284f0d77b1d8bf7a4678136936a1bb80b6571b9e41729fa338c4c9f1147b3f5e7a84591380e3e452162b1cfb7aec49922fa6480b3b6253af20fe1e0518')
    print(f'[D] AP_REQ_AUTHENTICATOR: a48180307ea003020112a27704753965a96bbab3515318d5272b80c608136d3721d4df6f62f5f55006090051a7d8fceaa06e96fd71ef9afb2778a3fb28a1c42d2f083e3e8b0a284f0d77b1d8bf7a4678136936a1bb80b6571b9e41729fa338c4c9f1147b3f5e7a84591380e3e452162b1cfb7aec49922fa6480b3b6253af20fe1e0518')
    print(f"[D] REQ-BODY MY LIB: {req_body_field.hex()}")
    print(f'[D] REQ-BODY IMPACKET: a4818f30818ca00703050040810010a2181b164c41422e544553542d544543484e4f4c4f47592e4e4ca33c303aa003020102a13330311b04686f73741b29646f6d61696e636f6e74726f6c6c657230312e6c61622e746573742d746563686e6f6c6f67792e6e6ca511180f32303236303330343132333731365aa70602045e2cb383a80e300c020117020110020103020112')
    print(f"[D] PDATA MY LIB: {padata_field.hex()}")
    print(f'[D] PDATA IMPACKET: a38205ed308205e9308205e5a103020101a28205dc048205d86e8205d4308205d0a003020105a10302010ea20703050000000000a3820536618205323082052ea003020105a1181b164c41422e544553542d544543484e4f4c4f47592e4e4ca22b3029a003020101a12230201b066b72627467741b164c41422e544553542d544543484e4f4c4f47592e4e4ca38204de308204daa003020112a103020102a28204cc048204c884011aa7c69b09f4d6680981400e95cbfebef52510d3f8850132af89ad9e4377240ca133de8c554b94107f599a0cd88481f52a7165bac944bbe71fb82c4f6050de8889e57d789ccbb2e9162860af913cb2c2f4ed05d86740998133e3ead98c8ef3017b534cd9f37e34c6347537e5db2ce07fd6663e75cd9eaa5de2e1a227a301afb17b38912386d4e5f00800864de0ee8c142a5aae9886d6d0b99d0001a55ccd77a091f5df3e3d57ac1cec4e51ddfee1f77dec14dd9ba22e321cdcb754938d0f33446083c6dd4c62b21064d3fcaed54a2146596df212bdb081f37ded0677caa6983e2243a57a3d85e26a9e784011271a8088a42c1ee8bb7243eb1bf7c125ad587017a333fceafb2962a2b3045a28f07f20404061126ec47960fa838ee5a1869997ea272ddfe88e28a639cec7a3b7abd2d9a6193a7a4e705f498f334a489ebec6d790564b29372b13ae922afab6d2e328cf402c7e257639ad250b0a19799140e5674c490ebb579bf07029477433fa1eaefa7687aec05ee6c940397117ef89df1fb10cc9c7fdb7feaa29abf0c45228da38ccb6338ddb62cc6ea5d853b4c253bcc3caaf9e78a356b2c657692200bcfb6fb9191ed8ff1479bca0a1882b166d45f6cba4d73ce8823758d3396d1be77363f9dc8057580e0df6ec7deef2de6e94a77d49a123c3c51ca6cb941c745028a4ecd2d3892d7321cb97cfeef1ea0abb365beeada605f83b49247b360f38e6a58fb8dea6ef3ad1e7edb5338ba4e1aa3b538cb3765d25e342b3498b3d5c622bc26571869d5bc696061ec1417f8793e1d917bd2da8da73deb853919f69ec7274ed6d84c84234447e7f2443ab872d58c8ad3d65465ff7a48e765a0d99685e0e908efe374f04044d84076928bd938a83a32e0a551bd45242676d86f19048f2e1bcd4b0d334189bb5a136f457666694c576b1e5bbab5291f15d4276721979e981a523c5cb187286eb1dddbbe81340a5f1c47585d3386ccd9c71dec1c2470b613146cd6f9a0974822237c7fd9b64a5f2f7e00e74e65356268b49428f00b1cbdde8518c236f3d895cdbf112162e50ec33626af1a85aec4412eb8f25112f1ade23b301cc1ae8c4183245ed3a7810a51563a0282125a4fa9b080cb96b95430fae51faf28028d75d226bbd04f20329b3e80f9e95f3bc903eaecf43b025ae213c88c5fdd3cf16b36ab746c325493c3906770411b5248028a0d537392c0cb9a5ceaba3b6fe8ed4fe8cdcbcdd87341c90df29645596c9a0d19ecb077d56ee188baaae7a226b4af896d8684ee0ed7a5f89a8c12ed98fcee60fd9bfaa4c925fa29f8e9bdc7d1bbd2ffba956c926fbb1c1affc37fba0dbed2d30afbd164d29719d6af3e5f3ab97706966bfe29b8f951bbde6295f84e6ef50cba6f1385492bf4dfe6d41e09ccb6a49fe0685a8190b9ed35c61cc9f0fb5f1f7f09b1dcfd93b45593b3f3b32133bfe834c9805664a43c6ebf5f64d7bdb54cfe51e1ff350413dab765d79ffe1dfc70c051e948ced919db9a0994d8add0fbce839f29d2ac0bc4c4e628f1127581db02125b5856fa572acfb763dd5723d0b9f31f79e01550177ee7376e1233eca8f12e1521976f39acf186b3c24b06cc92dcc179933c7b61d4681c79dcbc16d42257b0efb742d3435ff0359e2b78eba7ce4dd52e7eab8b1a6824d4138ecbdcfbe6f03b71fe013025e0e5d95f0ebdc2cd54ebda39fa3cd93261a8cd1586e7f3a76a48180307ea003020112a27704753965a96bbab3515318d5272b80c608136d3721d4df6f62f5f55006090051a7d8fceaa06e96fd71ef9afb2778a3fb28a1c42d2f083e3e8b0a284f0d77b1d8bf7a4678136936a1bb80b6571b9e41729fa338c4c9f1147b3f5e7a84591380e3e452162b1cfb7aec49922fa6480b3b6253af20fe1e0518')

    final_content = (
        asn1_tag(1, b'\x02\x01\x05') +
        asn1_tag(2, b'\x02\x01\x0c') +
        padata_field +
        req_body_field
    )

    packet = b'\x6c' + asn1_len(len(asn1_seq(final_content))) + final_content
    print(f"[D] TOTAAL PAKKET: {len(packet)} bytes")
    print("--- EIND TGS-REQ DEBUG ---\n")
    return packet


def extract_ticket_properly(as_rep_bytes):
    tag_5_idx = as_rep_bytes.find(b'\xa5')
    if tag_5_idx == -1:
        raise ValueError("Tag [5] (Ticket container) not found!")

    ticket_start = as_rep_bytes.find(b'\x61', tag_5_idx)
    len_bytes = as_rep_bytes[ticket_start + 2 : ticket_start + 4]
    ticket_len = int.from_bytes(len_bytes, byteorder='big')
    total_len = ticket_len + 4
    ticket_payload = as_rep_bytes[ticket_start : ticket_start + total_len]

    return ticket_payload


async def get_tgs(username: str, domain: str, host: str,
                  as_rep_bytes: bytes, base_key: bytes,
                  kdc_host: str, kdc_port: int = 88) -> bytes:
    session_key, key_type = get_session_key(as_rep_bytes, base_key)
    ticket_bytes = extract_ticket_properly(as_rep_bytes)

    print(f"[+] Gevonden Session Key: {session_key.hex()}")
    print(f"[+] Ticket bytes ({len(ticket_bytes)}): {ticket_bytes.hex()}")
    tgs_req = build_tgs_req(username, domain, session_key, key_type, ticket_bytes, ["host", host])
    b = b'l\x82\x06\x910\x82\x06\x8d\xa1\x03\x02\x01\x05\xa2\x03\x02\x01\x0c\xa3\x82\x05\xed0\x82\x05\xe90\x82\x05\xe5\xa1\x03\x02\x01\x01\xa2\x82\x05\xdc\x04\x82\x05\xd8n\x82\x05\xd40\x82\x05\xd0\xa0\x03\x02\x01\x05\xa1\x03\x02\x01\x0e\xa2\x07\x03\x05\x00\x00\x00\x00\x00\xa3\x82\x056a\x82\x0520\x82\x05.\xa0\x03\x02\x01\x05\xa1\x18\x1b\x16LAB.TEST-TECHNOLOGY.NL\xa2+0)\xa0\x03\x02\x01\x01\xa1"0 \x1b\x06krbtgt\x1b\x16LAB.TEST-TECHNOLOGY.NL\xa3\x82\x04\xde0\x82\x04\xda\xa0\x03\x02\x01\x12\xa1\x03\x02\x01\x02\xa2\x82\x04\xcc\x04\x82\x04\xc8\x84\x01\x1a\xa7\xc6\x9b\t\xf4\xd6h\t\x81@\x0e\x95\xcb\xfe\xbe\xf5%\x10\xd3\xf8\x85\x012\xaf\x89\xad\x9eCw$\x0c\xa13\xde\x8cUK\x94\x10\x7fY\x9a\x0c\xd8\x84\x81\xf5*qe\xba\xc9D\xbb\xe7\x1f\xb8,O`P\xde\x88\x89\xe5}x\x9c\xcb\xb2\xe9\x16(`\xaf\x91<\xb2\xc2\xf4\xed\x05\xd8g@\x99\x813\xe3\xea\xd9\x8c\x8e\xf3\x01{SL\xd9\xf3~4\xc64u7\xe5\xdb,\xe0\x7f\xd6f>u\xcd\x9e\xaa]\xe2\xe1\xa2\'\xa3\x01\xaf\xb1{8\x91#\x86\xd4\xe5\xf0\x08\x00\x86M\xe0\xee\x8c\x14*Z\xae\x98\x86\xd6\xd0\xb9\x9d\x00\x01\xa5\\\xcdw\xa0\x91\xf5\xdf>=W\xac\x1c\xecNQ\xdd\xfe\xe1\xf7}\xec\x14\xdd\x9b\xa2.2\x1c\xdc\xb7T\x93\x8d\x0f3D`\x83\xc6\xddLb\xb2\x10d\xd3\xfc\xae\xd5J!FYm\xf2\x12\xbd\xb0\x81\xf3}\xed\x06w\xca\xa6\x98>"C\xa5z=\x85\xe2j\x9ex@\x11\'\x1a\x80\x88\xa4,\x1e\xe8\xbbrC\xeb\x1b\xf7\xc1%\xadXp\x17\xa33\xfc\xea\xfb)b\xa2\xb3\x04Z(\xf0\x7f @@a\x12n\xc4y`\xfa\x83\x8e\xe5\xa1\x86\x99\x97\xea\'-\xdf\xe8\x8e(\xa69\xce\xc7\xa3\xb7\xab\xd2\xd9\xa6\x19:zNp_I\x8f3JH\x9e\xbe\xc6\xd7\x90VK)7+\x13\xae\x92*\xfa\xb6\xd2\xe3(\xcf@,~%v9\xad%\x0b\n\x19y\x91@\xe5gLI\x0e\xbbW\x9b\xf0p)Gt3\xfa\x1e\xae\xfav\x87\xae\xc0^\xe6\xc9@9q\x17\xef\x89\xdf\x1f\xb1\x0c\xc9\xc7\xfd\xb7\xfe\xaa)\xab\xf0\xc4R(\xda8\xcc\xb63\x8d\xdbb\xccn\xa5\xd8S\xb4\xc2S\xbc\xc3\xca\xaf\x9ex\xa3V\xb2\xc6Wi"\x00\xbc\xfbo\xb9\x19\x1e\xd8\xff\x14y\xbc\xa0\xa1\x88+\x16mE\xf6\xcb\xa4\xd7<\xe8\x827X\xd39m\x1b\xe7sc\xf9\xdc\x80WX\x0e\r\xf6\xec}\xee\xf2\xden\x94\xa7}I\xa1#\xc3\xc5\x1c\xa6\xcb\x94\x1ctP(\xa4\xec\xd2\xd3\x89-s!\xcb\x97\xcf\xee\xf1\xea\n\xbb6[\xee\xad\xa6\x05\xf8;I${6\x0f8\xe6\xa5\x8f\xb8\xde\xa6\xef:\xd1\xe7\xed\xb53\x8b\xa4\xe1\xaa;S\x8c\xb3v]%\xe3B\xb3I\x8b=\\b+\xc2eq\x86\x9d[\xc6\x96\x06\x1e\xc1A\x7f\x87\x93\xe1\xd9\x17\xbd-\xa8\xdas\xde\xb8S\x91\x9fi\xecrt\xedm\x84\xc8B4D~\x7f$C\xab\x87-X\xc8\xad=eF_\xf7\xa4\x8evZ\r\x99h^\x0e\x90\x8e\xfe7O\x04\x04M\x84\x07i(\xbd\x93\x8a\x83\xa3.\nU\x1b\xd4RBgm\x86\xf1\x90H\xf2\xe1\xbc\xd4\xb0\xd34\x18\x9b\xb5\xa16\xf4Wff\x94\xc5v\xb1\xe5\xbb\xabR\x91\xf1]Bvr\x19y\xe9\x81\xa5#\xc5\xcb\x18r\x86\xeb\x1d\xdd\xbb\xe8\x13@\xa5\xf1\xc4u\x85\xd38l\xcd\x9cq\xde\xc1\xc2G\x0ba1F\xcdo\x9a\tt\x82"7\xc7\xfd\x9bd\xa5\xf2\xf7\xe0\x0et\xe6SV&\x8bIB\x8f\x00\xb1\xcb\xdd\xe8Q\x8c#o=\x89\\\xdb\xf1\x12\x16.P\xec3bj\xf1\xa8Z\xecD\x12\xeb\x8f%\x11/\x1a\xde#\xb3\x01\xcc\x1a\xe8\xc4\x182E\xed:x\x10\xa5\x15c\xa0(!%\xa4\xfa\x9b\x08\x0c\xb9k\x95C\x0f\xaeQ\xfa\xf2\x80(\xd7]"k\xbd\x04\xf2\x03)\xb3\xe8\x0f\x9e\x95\xf3\xbc\x90>\xae\xcfC\xb0%\xae!<\x88\xc5\xfd\xd3\xcf\x16\xb3j\xb7F\xc3%I<9\x06w\x04\x11\xb5$\x80(\xa0\xd579,\x0c\xb9\xa5\xce\xab\xa3\xb6\xfe\x8e\xd4\xfe\x8c\xdc\xbc\xdd\x874\x1c\x90\xdf)dU\x96\xc9\xa0\xd1\x9e\xcb\x07}V\xee\x18\x8b\xaa\xaez"kJ\xf8\x96\xd8hN\xe0\xedz_\x89\xa8\xc1.\xd9\x8f\xce\xe6\x0f\xd9\xbf\xaaL\x92_\xa2\x9f\x8e\x9b\xdc}\x1b\xbd/\xfb\xa9V\xc9&\xfb\xb1\xc1\xaf\xfc7\xfb\xa0\xdb\xed-0\xaf\xbd\x16M)q\x9dj\xf3\xe5\xf3\xab\x97pif\xbf\xe2\x9b\x8f\x95\x1b\xbd\xe6)_\x84\xe6\xefP\xcb\xa6\xf18T\x92\xbfM\xfemA\xe0\x9c\xcbjI\xfe\x06\x85\xa8\x19\x0b\x9e\xd3\\a\xcc\x9f\x0f\xb5\xf1\xf7\xf0\x9b\x1d\xcf\xd9;EY;?;2\x13;\xfe\x83L\x98\x05fJC\xc6\xeb\xf5\xf6M{\xdbT\xcf\xe5\x1e\x1f\xf3PA=\xabv]y\xff\xe1\xdf\xc7\x0c\x05\x1e\x94\x8c\xed\x91\x9d\xb9\xa0\x99M\x8a\xdd\x0f\xbc\xe89\xf2\x9d*\xc0\xbcLNb\x8f\x11\'X\x1d\xb0!%\xb5\x85o\xa5r\xac\xfbv=\xd5r=\x0b\x9f1\xf7\x9e\x01U\x01w\xeesv\xe1#>\xca\x8f\x12\xe1R\x19v\xf3\x9a\xcf\x18k<$\xb0l\xc9-\xcc\x17\x993\xc7\xb6\x1dF\x81\xc7\x9d\xcb\xc1mB%{\x0e\xfbt-45\xff\x03Y\xe2\xb7\x8e\xba|\xe4\xddR\xe7\xea\xb8\xb1\xa6\x82MA8\xec\xbd\xcf\xbeo\x03\xb7\x1f\xe0\x13\x02^\x0e]\x95\xf0\xeb\xdc,\xd5N\xbd\xa3\x9f\xa3\xcd\x93&\x1a\x8c\xd1Xn\x7f:v\xa4\x81\x800~\xa0\x03\x02\x01\x12\xa2w\x04u9e\xa9k\xba\xb3QS\x18\xd5\'+\x80\xc6\x08\x13m7!\xd4\xdfob\xf5\xf5P\x06\t\x00Q\xa7\xd8\xfc\xea\xa0n\x96\xfdq\xef\x9a\xfb\'x\xa3\xfb(\xa1\xc4-/\x08>>\x8b\n(O\rw\xb1\xd8\xbfzFx\x13i6\xa1\xbb\x80\xb6W\x1b\x9eAr\x9f\xa38\xc4\xc9\xf1\x14{?^z\x84Y\x13\x80\xe3\xe4R\x16+\x1c\xfbz\xecI\x92/\xa6H\x0b;bS\xaf \xfe\x1e\x05\x18\xa4\x81\x8f0\x81\x8c\xa0\x07\x03\x05\x00@\x81\x00\x10\xa2\x18\x1b\x16LAB.TEST-TECHNOLOGY.NL\xa3<0:\xa0\x03\x02\x01\x02\xa1301\x1b\x04host\x1b)domaincontroller01.lab.test-technology.nl\xa5\x11\x18\x0f20260304123716Z\xa7\x06\x02\x04^,\xb3\x83\xa8\x0e0\x0c\x02\x01\x17\x02\x01\x10\x02\x01\x03\x02\x01\x12'
    print(f"[D] Impacket version (working) ({len(b)}): {b.hex()}")
    print(f"[+] TGS req ({len(tgs_req)}): {tgs_req.hex()}")
    as_res_bytes = await send_kerberos_packet(tgs_req, kdc_host, kdc_port)
    print(f"[+] Response: {as_res_bytes.hex()}")
    # len ticket impacket = 1338
    # my ticket len = 1334

    # print(d.hex())
    # tgs_req = extract_session_key(as_rep_bytes, base_key)

    # Ticket bytes (HEX) impacket
    # a3820536618205323082052ea003020105a1181b164c41422e544553542d544543484e4f4c4f47592e4e4ca22b3029a003020101a12230201b066b72627467741b164c41422e544553542d544543484e4f4c4f47592e4e4ca38204de308204daa003020112a103020102a28204cc048204c884011aa7c69b09f4d6680981400e95cbfebef52510d3f8850132af89ad9e4377240ca133de8c554b94107f599a0cd88481f52a7165bac944bbe71fb82c4f6050de8889e57d789ccbb2e9162860af913cb2c2f4ed05d86740998133e3ead98c8ef3017b534cd9f37e34c6347537e5db2ce07fd6663e75cd9eaa5de2e1a227a301afb17b38912386d4e5f00800864de0ee8c142a5aae9886d6d0b99d0001a55ccd77a091f5df3e3d57ac1cec4e51ddfee1f77dec14dd9ba22e321cdcb754938d0f33446083c6dd4c62b21064d3fcaed54a2146596df212bdb081f37ded0677caa6983e2243a57a3d85e26a9e784011271a8088a42c1ee8bb7243eb1bf7c125ad587017a333fceafb2962a2b3045a28f07f20404061126ec47960fa838ee5a1869997ea272ddfe88e28a639cec7a3b7abd2d9a6193a7a4e705f498f334a489ebec6d790564b29372b13ae922afab6d2e328cf402c7e257639ad250b0a19799140e5674c490ebb579bf07029477433fa1eaefa7687aec05ee6c940397117ef89df1fb10cc9c7fdb7feaa29abf0c45228da38ccb6338ddb62cc6ea5d853b4c253bcc3caaf9e78a356b2c657692200bcfb6fb9191ed8ff1479bca0a1882b166d45f6cba4d73ce8823758d3396d1be77363f9dc8057580e0df6ec7deef2de6e94a77d49a123c3c51ca6cb941c745028a4ecd2d3892d7321cb97cfeef1ea0abb365beeada605f83b49247b360f38e6a58fb8dea6ef3ad1e7edb5338ba4e1aa3b538cb3765d25e342b3498b3d5c622bc26571869d5bc696061ec1417f8793e1d917bd2da8da73deb853919f69ec7274ed6d84c84234447e7f2443ab872d58c8ad3d65465ff7a48e765a0d99685e0e908efe374f04044d84076928bd938a83a32e0a551bd45242676d86f19048f2e1bcd4b0d334189bb5a136f457666694c576b1e5bbab5291f15d4276721979e981a523c5cb187286eb1dddbbe81340a5f1c47585d3386ccd9c71dec1c2470b613146cd6f9a0974822237c7fd9b64a5f2f7e00e74e65356268b49428f00b1cbdde8518c236f3d895cdbf112162e50ec33626af1a85aec4412eb8f25112f1ade23b301cc1ae8c4183245ed3a7810a51563a0282125a4fa9b080cb96b95430fae51faf28028d75d226bbd04f20329b3e80f9e95f3bc903eaecf43b025ae213c88c5fdd3cf16b36ab746c325493c3906770411b5248028a0d537392c0cb9a5ceaba3b6fe8ed4fe8cdcbcdd87341c90df29645596c9a0d19ecb077d56ee188baaae7a226b4af896d8684ee0ed7a5f89a8c12ed98fcee60fd9bfaa4c925fa29f8e9bdc7d1bbd2ffba956c926fbb1c1affc37fba0dbed2d30afbd164d29719d6af3e5f3ab97706966bfe29b8f951bbde6295f84e6ef50cba6f1385492bf4dfe6d41e09ccb6a49fe0685a8190b9ed35c61cc9f0fb5f1f7f09b1dcfd93b45593b3f3b32133bfe834c9805664a43c6ebf5f64d7bdb54cfe51e1ff350413dab765d79ffe1dfc70c051e948ced919db9a0994d8add0fbce839f29d2ac0bc4c4e628f1127581db02125b5856fa572acfb763dd5723d0b9f31f79e01550177ee7376e1233eca8f12e1521976f39acf186b3c24b06cc92dcc179933c7b61d4681c79dcbc16d42257b0efb742d3435ff0359e2b78eba7ce4dd52e7eab8b1a6824d4138ecbdcfbe6f03b71fe013025e0e5d95f0ebdc2cd54ebda39fa3cd93261a8cd1586e7f3a76
    # Ticket bytes (HEX) my lib
    # 618205323082052ea003020105a1181b164c41422e544553542d544543484e4f4c4f47592e4e4ca22b3029a003020101a12230201b066b72627467741b164c41422e544553542d544543484e4f4c4f47592e4e4ca38204de308204daa003020112a103020102a28204cc048204c899626e1c98b9d3d9373c30612730eaa6b8e37c63ef7a9950bb248d6583ef4c50314efd674e6c8d92437a9baf13955f7d7ee2151409229879e61d394618ecafcfe70d5c1679f43f2f3c95c08c5871f2df388c16ccabbab766896c083ceccbf43951f7740cfb55e291cc71906acf59a11d3eb011f55757279f1d6ae37f140cf1b734a15b0b773444f81c51110416390717b4978f5f5ad9fa975256f960b532cc76f9bb6d1ab0380c46dfbc7c890b01ddff1a80fdce6b25c7a514268bfd80436aa0341867a140a9c8cce34008e1d4c99e87b35b63257180879f22472a397a64de217945d82862621f2706ad55557444ad02505bb5ac695fc65b0000c3ec7d094b5aeab76ade8bca0848e685ac4dba618fb5dbd0a289180c5ddfdc684e22840e49d1764591690a2ef5ce9fa0b26140d90e57ded36cddc02c3237614bf8e6c641d780f5e5f084247f9d6ba5b3d034b0c1ac710b3d04260579aa3551a0c6c288c684f1dd46297af3493ea6766b3df3cd9ea0294a3fb5cfe60a690b25cbcbc77cca3de787e7360ad00c5c921bf6ae3aff1f8a40d7abfc7f66320c9407880c3844698c89b212b05fb51f7a5c22786f1fb713219cb0d67794b6ac030a88f59d84f6a9a319400e6ba0802a37482ac6054c58ded13646695268f7434c2c094a1407bda22267b529533e9624301ad394846775683021d9e5b4ef4bb9ed3a15f415af60162cbbd7e07848b7a62fcec4296e908af178c623baeae63692082c1b60b9ad886fe0b4a9e240992dbfec49aa1753c461d2969c0c23bb17caffca1cf190cbb47377e5b29161f714d52abb9ee1b9f4b54b2eb0b20d1a1ba155b9a7d1dbe800013a6f365eea1d4866693053aec61f50e5120147eaf9c17ecda63d574fa7ce4849537437320d8c56796deba394af366ea941cb899bc1af3f48555702e8fc2b678102cce3dac603515bbf4d96151381a3a211799787fb74c8d1dd85849ad32d5cb16e689a73c7f326d4d77982ea4d9f08810e794f972c6707091f09d74d2dc2231b159e1bc8257ddcc468ffd9146cfa098b6e6d735f4f38d973b185b93cdf5509b511555810af5b74cbd39a982002880fc58279c11bcec9458b49e6804f82ec2d392360fb21cda0bce9c79c1e6f1eb29219cb1c8a9e9c8c412a03ca911ae9f7eb34d31d8d9552c782612617578bcb7f74f1f88ba76a4220178c5b6486fbdc1b4667fadb3e852216ba956c5f1c2844eb852c8fd910bc65313e13dc05c50d22bced9abee2f16a818c2ca30594639583ec447e6296a1aa38bbf48923fca60b03de868f73dd6474a82552dac3eb04c737ab40d016d75e872edc819edb6d179585d0cebd05acfa97f60b22f411a7737214db49b7b78268e23215a74dc7916220f5eb67689e7e31d24161b25b4102df79a6fadf2077343f5d97fdf16af575da9027938e414530f2c4734ff90397b8c8a340e6eabd94a4bbb258f57b69b7a129e091c2f9ed73511d206377f3c29379bee1f7d100670f5cbb99b4dcc5c72dcef965e9a01b187759b801e9a7b2f11d01f812cda9e4e9c9733ad89878641144af04347f20ba84f869805ee72d3a4b81758cb1386aa889dace5cd7bb7227ca59d8fc99d3f7a0dee70688414a28d7ff7d426d80e1edf3b0bc3c5ffe34fa804bc581d72be5c96c03f6052345789c932def65ff3e15263efcac75937954f566802c5327c65bb1dfb4db1b87c938654742b9cc4a04

    # TGS (HEX) impacket (working)
    # 6c8206913082068da103020105a20302010ca38205ed308205e9308205e5a103020101a28205dc048205d86e8205d4308205d0a003020105a10302010ea20703050000000000a3820536618205323082052ea003020105a1181b164c41422e544553542d544543484e4f4c4f47592e4e4ca22b3029a003020101a12230201b066b72627467741b164c41422e544553542d544543484e4f4c4f47592e4e4ca38204de308204daa003020112a103020102a28204cc048204c884011aa7c69b09f4d6680981400e95cbfebef52510d3f8850132af89ad9e4377240ca133de8c554b94107f599a0cd88481f52a7165bac944bbe71fb82c4f6050de8889e57d789ccbb2e9162860af913cb2c2f4ed05d86740998133e3ead98c8ef3017b534cd9f37e34c6347537e5db2ce07fd6663e75cd9eaa5de2e1a227a301afb17b38912386d4e5f00800864de0ee8c142a5aae9886d6d0b99d0001a55ccd77a091f5df3e3d57ac1cec4e51ddfee1f77dec14dd9ba22e321cdcb754938d0f33446083c6dd4c62b21064d3fcaed54a2146596df212bdb081f37ded0677caa6983e2243a57a3d85e26a9e784011271a8088a42c1ee8bb7243eb1bf7c125ad587017a333fceafb2962a2b3045a28f07f20404061126ec47960fa838ee5a1869997ea272ddfe88e28a639cec7a3b7abd2d9a6193a7a4e705f498f334a489ebec6d790564b29372b13ae922afab6d2e328cf402c7e257639ad250b0a19799140e5674c490ebb579bf07029477433fa1eaefa7687aec05ee6c940397117ef89df1fb10cc9c7fdb7feaa29abf0c45228da38ccb6338ddb62cc6ea5d853b4c253bcc3caaf9e78a356b2c657692200bcfb6fb9191ed8ff1479bca0a1882b166d45f6cba4d73ce8823758d3396d1be77363f9dc8057580e0df6ec7deef2de6e94a77d49a123c3c51ca6cb941c745028a4ecd2d3892d7321cb97cfeef1ea0abb365beeada605f83b49247b360f38e6a58fb8dea6ef3ad1e7edb5338ba4e1aa3b538cb3765d25e342b3498b3d5c622bc26571869d5bc696061ec1417f8793e1d917bd2da8da73deb853919f69ec7274ed6d84c84234447e7f2443ab872d58c8ad3d65465ff7a48e765a0d99685e0e908efe374f04044d84076928bd938a83a32e0a551bd45242676d86f19048f2e1bcd4b0d334189bb5a136f457666694c576b1e5bbab5291f15d4276721979e981a523c5cb187286eb1dddbbe81340a5f1c47585d3386ccd9c71dec1c2470b613146cd6f9a0974822237c7fd9b64a5f2f7e00e74e65356268b49428f00b1cbdde8518c236f3d895cdbf112162e50ec33626af1a85aec4412eb8f25112f1ade23b301cc1ae8c4183245ed3a7810a51563a0282125a4fa9b080cb96b95430fae51faf28028d75d226bbd04f20329b3e80f9e95f3bc903eaecf43b025ae213c88c5fdd3cf16b36ab746c325493c3906770411b5248028a0d537392c0cb9a5ceaba3b6fe8ed4fe8cdcbcdd87341c90df29645596c9a0d19ecb077d56ee188baaae7a226b4af896d8684ee0ed7a5f89a8c12ed98fcee60fd9bfaa4c925fa29f8e9bdc7d1bbd2ffba956c926fbb1c1affc37fba0dbed2d30afbd164d29719d6af3e5f3ab97706966bfe29b8f951bbde6295f84e6ef50cba6f1385492bf4dfe6d41e09ccb6a49fe0685a8190b9ed35c61cc9f0fb5f1f7f09b1dcfd93b45593b3f3b32133bfe834c9805664a43c6ebf5f64d7bdb54cfe51e1ff350413dab765d79ffe1dfc70c051e948ced919db9a0994d8add0fbce839f29d2ac0bc4c4e628f1127581db02125b5856fa572acfb763dd5723d0b9f31f79e01550177ee7376e1233eca8f12e1521976f39acf186b3c24b06cc92dcc179933c7b61d4681c79dcbc16d42257b0efb742d3435ff0359e2b78eba7ce4dd52e7eab8b1a6824d4138ecbdcfbe6f03b71fe013025e0e5d95f0ebdc2cd54ebda39fa3cd93261a8cd1586e7f3a76a48180307ea003020112a27704753965a96bbab3515318d5272b80c608136d3721d4df6f62f5f55006090051a7d8fceaa06e96fd71ef9afb2778a3fb28a1c42d2f083e3e8b0a284f0d77b1d8bf7a4678136936a1bb80b6571b9e41729fa338c4c9f1147b3f5e7a84591380e3e452162b1cfb7aec49922fa6480b3b6253af20fe1e0518a4818f30818ca00703050040810010a2181b164c41422e544553542d544543484e4f4c4f47592e4e4ca33c303aa003020102a13330311b04686f73741b29646f6d61696e636f6e74726f6c6c657230312e6c61622e746573742d746563686e6f6c6f67792e6e6ca511180f32303236303330343132333731365aa70602045e2cb383a80e300c020117020110020103020112
    # TGS (HEX) my lib (not tested, but still not equal in size)
    # 6c82064430820640a103020105a20302010ca382059f3082059b30820597a103020101a282058e6e82058a30820586a003020105a10302010ea20703050000000000a3820536618205323082052ea003020105a1181b164c41422e544553542d544543484e4f4c4f47592e4e4ca22b3029a003020101a12230201b066b72627467741b164c41422e544553542d544543484e4f4c4f47592e4e4ca38204de308204daa003020112a103020102a28204cc048204c899626e1c98b9d3d9373c30612730eaa6b8e37c63ef7a9950bb248d6583ef4c50314efd674e6c8d92437a9baf13955f7d7ee2151409229879e61d394618ecafcfe70d5c1679f43f2f3c95c08c5871f2df388c16ccabbab766896c083ceccbf43951f7740cfb55e291cc71906acf59a11d3eb011f55757279f1d6ae37f140cf1b734a15b0b773444f81c51110416390717b4978f5f5ad9fa975256f960b532cc76f9bb6d1ab0380c46dfbc7c890b01ddff1a80fdce6b25c7a514268bfd80436aa0341867a140a9c8cce34008e1d4c99e87b35b63257180879f22472a397a64de217945d82862621f2706ad55557444ad02505bb5ac695fc65b0000c3ec7d094b5aeab76ade8bca0848e685ac4dba618fb5dbd0a289180c5ddfdc684e22840e49d1764591690a2ef5ce9fa0b26140d90e57ded36cddc02c3237614bf8e6c641d780f5e5f084247f9d6ba5b3d034b0c1ac710b3d04260579aa3551a0c6c288c684f1dd46297af3493ea6766b3df3cd9ea0294a3fb5cfe60a690b25cbcbc77cca3de787e7360ad00c5c921bf6ae3aff1f8a40d7abfc7f66320c9407880c3844698c89b212b05fb51f7a5c22786f1fb713219cb0d67794b6ac030a88f59d84f6a9a319400e6ba0802a37482ac6054c58ded13646695268f7434c2c094a1407bda22267b529533e9624301ad394846775683021d9e5b4ef4bb9ed3a15f415af60162cbbd7e07848b7a62fcec4296e908af178c623baeae63692082c1b60b9ad886fe0b4a9e240992dbfec49aa1753c461d2969c0c23bb17caffca1cf190cbb47377e5b29161f714d52abb9ee1b9f4b54b2eb0b20d1a1ba155b9a7d1dbe800013a6f365eea1d4866693053aec61f50e5120147eaf9c17ecda63d574fa7ce4849537437320d8c56796deba394af366ea941cb899bc1af3f48555702e8fc2b678102cce3dac603515bbf4d96151381a3a211799787fb74c8d1dd85849ad32d5cb16e689a73c7f326d4d77982ea4d9f08810e794f972c6707091f09d74d2dc2231b159e1bc8257ddcc468ffd9146cfa098b6e6d735f4f38d973b185b93cdf5509b511555810af5b74cbd39a982002880fc58279c11bcec9458b49e6804f82ec2d392360fb21cda0bce9c79c1e6f1eb29219cb1c8a9e9c8c412a03ca911ae9f7eb34d31d8d9552c782612617578bcb7f74f1f88ba76a4220178c5b6486fbdc1b4667fadb3e852216ba956c5f1c2844eb852c8fd910bc65313e13dc05c50d22bced9abee2f16a818c2ca30594639583ec447e6296a1aa38bbf48923fca60b03de868f73dd6474a82552dac3eb04c737ab40d016d75e872edc819edb6d179585d0cebd05acfa97f60b22f411a7737214db49b7b78268e23215a74dc7916220f5eb67689e7e31d24161b25b4102df79a6fadf2077343f5d97fdf16af575da9027938e414530f2c4734ff90397b8c8a340e6eabd94a4bbb258f57b69b7a129e091c2f9ed73511d206377f3c29379bee1f7d100670f5cbb99b4dcc5c72dcef965e9a01b187759b801e9a7b2f11d01f812cda9e4e9c9733ad89878641144af04347f20ba84f869805ee72d3a4b81758cb1386aa889dace5cd7bb7227ca59d8fc99d3f7a0dee70688414a28d7ff7d426d80e1edf3b0bc3c5ffe34fa804bc581d72be5c96c03f6052345789c932def65ff3e15263efcac75937954f566802c5327c65bb1dfb4db1b87c938654742b9cc4a04a4373035a003020112a22e042c20dc393f56e53442c7c0d47a7d2395539158093370b55ef82731613c57536e8b547fd38812fee26a68f8818aa4819030818da00703050040810010a2181b164c41422e544553542d544543484e4f4c4f47592e4e4ca33d303ba003020101a13430321b0552504353531b29646f6d61696e636f6e74726f6c6c657230312e6c61622e746573742d746563686e6f6c6f67792e6e6ca511180f32303236303330343133313630335aa706020434da5fb2a80e300c020117020110020103020112

    assert 0


