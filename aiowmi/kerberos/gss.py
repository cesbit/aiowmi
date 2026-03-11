import secrets
import struct
from Crypto.Hash import HMAC, MD5
from Crypto.Cipher import ARC4


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

    confounder = secrets.token_bytes(8)

    k_sign = HMAC.new(session_key, b'signaturekey\0', MD5).digest()

    md5_pre_hash = MD5.new(struct.pack('<L', 13) + token_header + confounder + data).digest()

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