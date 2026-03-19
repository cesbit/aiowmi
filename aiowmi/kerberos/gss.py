import struct
from typing import Tuple
from Crypto.Hash import HMAC, MD5
from Crypto.Cipher import ARC4
from ..tools import get_random_bytes
from .tools import encrypt_kerberos_aes_cts, decrypt_kerberos_aes_cts


GSS_WRAP_HEADER = b'\x60\x2b\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02'
GSS_WRAP_HEADER_LEN = len(GSS_WRAP_HEADER)  # 13


def gss_wrap_rc4(session_key: bytes,
                 data: bytes,
                 seq_num: int,
                 direction='init',
                 encrypt=True):
    pad = (8 - (len(data) % 8)) & 0x7
    pad_str = bytes([pad]) * pad
    data += pad_str

    seal_alg = b'\x10\x00' if encrypt else b'\xff\xff'
    token_header = b'\x02\x01\x11\x00' + seal_alg + b'\xff\xff'

    if direction == 'init':
        snd_seq = struct.pack('>L', seq_num) + b'\x00' * 4
    else:
        snd_seq = struct.pack('>L', seq_num) + b'\xff' * 4

    confounder = get_random_bytes(8)

    k_sign = HMAC.new(session_key, b'signaturekey\0', MD5).digest()

    md5_pre_hash = MD5.new(
        struct.pack('<L', 13) + token_header + confounder + data).digest()

    sgn_cksum = HMAC.new(k_sign, md5_pre_hash, MD5).digest()
    sgn_cksum_8 = sgn_cksum[:8]

    k_seq_base = HMAC.new(session_key, b'\x00\x00\x00\x00', MD5).digest()
    k_seq = HMAC.new(k_seq_base, sgn_cksum_8, MD5).digest()

    enc_snd_seq = ARC4.new(k_seq).encrypt(snd_seq)

    if encrypt:
        k_local = bytes([b ^ 0xF0 for b in session_key])

        k_crypt = HMAC.new(k_local, b'\x00\x00\x00\x00', MD5).digest()
        k_crypt = HMAC.new(k_crypt, struct.pack('>L', seq_num), MD5).digest()

        rc4 = ARC4.new(k_crypt)
        enc_confounder = rc4.encrypt(confounder)
        cipher_text = rc4.encrypt(data)
    else:
        enc_confounder = confounder
        cipher_text = data

    token_data = token_header + enc_snd_seq + sgn_cksum_8
    final_auth_data = GSS_WRAP_HEADER + token_data + enc_confounder

    return cipher_text, final_auth_data


def gss_unwrap_rc4(session_key: bytes,
                   cipher_text: bytes,
                   auth_data: bytes):
    token_bytes = auth_data[GSS_WRAP_HEADER_LEN:]
    sgn_cksum_8 = token_bytes[16:24]

    k_sign = HMAC.new(session_key, b'signaturekey\x00', MD5).digest()
    k_seq_base = HMAC.new(session_key, b'\x00\x00\x00\x00', MD5).digest()
    k_seq = HMAC.new(k_seq_base, sgn_cksum_8, MD5).digest()

    enc_snd_seq = token_bytes[8:16]
    snd_seq = ARC4.new(k_seq).decrypt(enc_snd_seq)

    k_local = bytes([b ^ 0xF0 for b in session_key])
    k_crypt_base = HMAC.new(k_local, b'\x00\x00\x00\x00', MD5).digest()
    k_crypt = HMAC.new(k_crypt_base, snd_seq[:4], MD5).digest()

    enc_confounder = auth_data[-8:]
    rc4 = ARC4.new(k_crypt)

    decrypted_blob = rc4.decrypt(enc_confounder + cipher_text)
    confounder = decrypted_blob[:8]
    data = decrypted_blob[8:]

    token_header = token_bytes[:8]
    md5_hash = MD5.new(
        struct.pack('<L', 13) + token_header + confounder + data).digest()
    expected_sgn_cksum = HMAC.new(k_sign, md5_hash, MD5).digest()

    if sgn_cksum_8 != expected_sgn_cksum[:8]:
        svr_seq = struct.unpack('>L', snd_seq[:4])[0]
        raise Exception(f"Integrity Check Failed! Server Seq was: {svr_seq}")

    return data


def gss_wrap_aes(session_key: bytes,
                 data: bytes,
                 seq_num: int) -> Tuple[bytes, bytes]:
    pad = (16 - (len(data) % 16)) & 15
    pad_str = b'\xFF' * pad

    header_for_hash = (
        b'\x05\x04\x06\xff\x00\x00\x00\x00' +
        struct.pack('>Q', seq_num)
    )

    plaintext = data + pad_str + header_for_hash
    raw_cipher = encrypt_kerberos_aes_cts(session_key, 24, plaintext)

    def rotate(bytes_data: bytes, n: int) -> bytes:
        n %= len(bytes_data)
        left = len(bytes_data) - n
        return bytes_data[left:] + bytes_data[:left]

    rrc = 28
    total_rotate = rrc + pad
    cipher_rotated = rotate(raw_cipher, total_rotate)

    wire_header = (
        b'\x05\x04\x06\xff' +
        struct.pack('>H', pad) +
        struct.pack('>H', rrc) +
        struct.pack('>Q', seq_num)
    )
    split_offset = 16 + rrc + pad

    ret2 = wire_header + cipher_rotated[:split_offset]
    ret1 = cipher_rotated[split_offset:]

    return ret1, ret2


def gss_unwrap_aes(session_key: bytes, cipher_text: bytes,
                   auth_data: bytes) -> bytes:
    header = auth_data[:16]
    pad = struct.unpack('>H', header[4:6])[0]  # EC
    rrc = struct.unpack('>H', header[6:8])[0]  # RRC

    cipher_from_trailer = auth_data[16:]

    rotated_blob = cipher_from_trailer + cipher_text

    def unrotate(data, n):
        if not data:
            return data
        n %= len(data)
        return data[n:] + data[:n]

    full_cipher_blob = unrotate(rotated_blob, rrc + pad)

    decrypted_payload = \
        decrypt_kerberos_aes_cts(session_key, 22, full_cipher_blob)
    actual_data = decrypted_payload[16: -(pad + 16)]

    return actual_data
