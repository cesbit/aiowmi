import functools
import os
import hashlib
import hmac
import math
import struct
from functools import reduce
from pyasn1.codec.der import decoder, encoder
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA1, MD5
from .rc4 import RC4
from .gss import gss_wrap_rc4, gss_unwrap_rc4
from ..exceptions import KerberosErr


def _nfold(ba, nbytes):
    def rotate_right(ba, nbits):
        ba = bytearray(ba)
        n = len(ba)
        nbits %= (n * 8)
        # Rotate bytes
        for _ in range(nbits // 8):
            ba = bytearray([ba[-1]]) + ba[:-1]
        # Rotate remaining bits
        nbits %= 8
        if nbits > 0:
            last_bit = 0
            for i in range(len(ba)):
                new_last_bit = ba[i] & ((1 << nbits) - 1)
                ba[i] = (ba[i] >> nbits) | (last_bit << (8 - nbits))
                last_bit = new_last_bit
            ba[0] |= (last_bit << (8 - nbits))
        return ba

    def add_ones_complement(ba1, ba2):
        n = len(ba1)
        res = [0] * n
        carry = 0
        for i in range(n-1, -1, -1):
            s = ba1[i] + ba2[i] + carry
            res[i] = s & 0xff
            carry = s >> 8

        pos = n - 1
        while carry and pos >= 0:
            s = res[pos] + carry
            res[pos] = s & 0xff
            carry = s >> 8
            pos -= 1
        return bytearray(res)

    slen = len(ba)

    def lcm(a, b):
        return abs(a*b) // math.gcd(a, b)

    lcm_val = lcm(slen, nbytes)
    big_str = bytearray()
    curr = bytearray(ba)
    for i in range(lcm_val // slen):
        big_str += curr
        curr = rotate_right(curr, 13)

    parts = [big_str[i:i+nbytes] for i in range(0, len(big_str), nbytes)]
    return bytes(reduce(add_ones_complement, parts))


def derive_key(base_key, usage_int, payload_byte=None):
    constant = struct.pack('>I', usage_int)
    if payload_byte is not None:
        constant += bytes([payload_byte])

    nfolded = _nfold(constant, 16)
    cipher = Cipher(algorithms.AES(base_key), modes.ECB())
    encryptor1 = cipher.encryptor()
    b1 = encryptor1.update(nfolded) + encryptor1.finalize()
    encryptor2 = cipher.encryptor()
    b2 = encryptor2.update(b1) + encryptor2.finalize()

    return b1 + b2


def aes_cts_encrypt(key: bytes, plain: bytes) -> bytes:
    n = len(plain)  # 43 bytes
    iv = b'\x00' * 16
    pad_len = 16 - (n % 16)
    padded_plain = plain + b'\x00' * pad_len

    # CBC encryptie (correct IV)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    full_cipher = encryptor.update(padded_plain) + encryptor.finalize()

    c1 = full_cipher[0:16]
    c2 = full_cipher[16:32]
    c3 = full_cipher[32:48]

    return c1 + c3 + c2[:n % 16]


def decrypt_kerberos_aes_cts(key: bytes, usage: int, cipher: bytes) -> bytes:
    ciphertext = cipher[:-12]
    expected_hmac = cipher[-12:]

    ki = derive_key(key, usage, 0x55)
    ke = derive_key(key, usage, 0xAA)

    n = len(ciphertext)
    block_size = 16

    aes = AES.new(ke, AES.MODE_ECB)

    if n % block_size == 0:
        aes_cbc = AES.new(ke, AES.MODE_CBC, b'\x00' * block_size)
        plaintext_with_confounder = aes_cbc.decrypt(ciphertext)
    else:
        m = n // block_size
        last_blocks_len = n % block_size

        iv = b'\x00' * block_size
        plaintext_with_confounder = b''

        for i in range(m - 1):
            block = ciphertext[i*block_size: (i+1)*block_size]
            dec = aes.decrypt(block)
            plaintext_with_confounder += \
                bytes(a ^ b for a, b in zip(dec, iv))
            iv = block

        cn_minus_1 = ciphertext[(m-1)*block_size: m*block_size]
        cn = ciphertext[m*block_size:]

        dec_intermediate = aes.decrypt(cn_minus_1)

        pn = bytes(
            a ^ b for a, b in zip(dec_intermediate[:last_blocks_len], cn))

        stolen_bytes = dec_intermediate[last_blocks_len:]
        full_block_to_decrypt = cn + stolen_bytes

        dec_pn_minus_1 = aes.decrypt(full_block_to_decrypt)
        pn_minus_1 = bytes(a ^ b for a, b in zip(dec_pn_minus_1, iv))

        plaintext_with_confounder += pn_minus_1 + pn

    h = HMAC.new(ki, plaintext_with_confounder, SHA1)
    if h.digest()[:12] != expected_hmac:
        raise ValueError("Integrity check failed: HMAC mismatch")

    return plaintext_with_confounder


def encrypt_kerberos_aes_cts(session_key: bytes,
                             usage: int,
                             plain_text: bytes):
    ki = derive_key(session_key, usage, 0x55)
    ke = derive_key(session_key, usage, 0xAA)

    confounder = os.urandom(16)
    basic_plaintext = confounder + plain_text

    h = HMAC.new(ki, basic_plaintext, SHA1)
    checksum = h.digest()[:12]

    aes = AES.new(ke, AES.MODE_CBC, b'\x00' * 16)
    n = len(basic_plaintext)

    if n % 16 == 0:
        final_ctext = aes.encrypt(basic_plaintext)
    else:
        pad_len = 16 - (n % 16)
        padded_data = basic_plaintext + b'\x00' * pad_len
        ctext = aes.encrypt(padded_data)

        last_full_block = ctext[-32:-16]
        truncated_block = ctext[-16:]

        final_ctext = (
            ctext[:-32] +
            truncated_block +
            last_full_block[:16-pad_len]
        )

    return final_ctext + checksum


def encrypt_kerberos_rc4(session_key, usage, plaintext):
    confounder = os.urandom(8)
    data_to_encrypt = confounder + plaintext

    usage_bytes = struct.pack('<I', usage)
    k1 = HMAC.new(session_key, usage_bytes, MD5).digest()

    checksum = HMAC.new(k1, data_to_encrypt, MD5).digest()
    k3 = HMAC.new(k1, checksum, MD5).digest()

    cipher = RC4(k3)
    encrypted_data = cipher.encrypt(data_to_encrypt)

    return checksum + encrypted_data


def decrypt_kerberos_rc4(key, usage, data):
    checksum = data[:16]
    encrypted_data = data[16:]

    k1 = hmac.new(key, struct.pack('<I', usage), hashlib.md5).digest()
    k3 = hmac.new(k1, checksum, hashlib.md5).digest()

    cipher = RC4(k3)
    decrypted = cipher.decrypt(encrypted_data)

    return decrypted[8:]  # Skip 8 bytes confounder


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


def seal_func_kerberos(session_key: bytes):
    def _kerberos_sealer(
            flags: int,
            seq_num: int,
            message_to_sign: bytes,
            message_to_encrypt: bytes,
            session_key: bytes) -> tuple[bytes, bytes]:
        return gss_wrap_rc4(session_key,
                            message_to_encrypt,
                            seq_num)
    return functools.partial(_kerberos_sealer, session_key=session_key)


def gss_unwrap_kerberos(session_key: bytes):
    def _kerberos_unwrap(
            cipher_text: bytes,
            auth_data: bytes,
            session_key: bytes) -> tuple[bytes, bytes]:
        return gss_unwrap_rc4(session_key,
                              cipher_text,
                              auth_data)
    return functools.partial(_kerberos_unwrap, session_key=session_key)


def sign_func_kerberos(session_key: bytes):
    def _kerberos_signer(
            flags: int,
            seq_num: int,
            message_to_sign: bytes,
            session_key: bytes) -> tuple[bytes, bytes]:
        return gss_wrap_rc4(session_key,
                            message_to_sign,
                            seq_num)
    return functools.partial(_kerberos_signer, session_key=session_key)


KDC_ERR_PREAUTH_REQUIRED = 25

KRB_ERRORS = {
    0:  "KDC_ERR_NONE (No error)",
    1:  "KDC_ERR_NAME_EXP (Client's entry in database has expired)",
    2:  "KDC_ERR_SERVICE_EXP (Server's entry in database has expired)",
    3:  "KDC_ERR_BAD_PVNO (Requested protocol version number not supported)",
    4:  "KDC_ERR_C_OLD_MAST_KVNO (Client's key encrypted in old master key)",
    5:  "KDC_ERR_S_OLD_MAST_KVNO (Server's key encrypted in old master key)",
    6:  "KDC_ERR_C_PRINCIPAL_UNKNOWN (Username not found in Kerberos db)",
    7:  "KDC_ERR_S_PRINCIPAL_UNKNOWN (Server not found; Must use FQDN)",
    8:  "KDC_ERR_PRINCIPAL_NOT_UNIQUE (Multiple principal entries in db)",
    9:  "KDC_ERR_NULL_KEY (The client or server has a null key)",
    10: "KDC_ERR_CANNOT_POSTDATE (Ticket not eligible for postdating)",
    11: "KDC_ERR_NEVER_VALID (Requested starttime is later than end time)",
    12: "KDC_ERR_POLICY (KDC policy rejects request)",
    13: "KDC_ERR_BADOPTION (KDC cannot accommodate requested option)",
    14: "KDC_ERR_ETYPE_NOSUPP (KDC has no support for encryption type)",
    15: "KDC_ERR_SUMTYPE_NOSUPP (KDC has no support for checksum type)",
    16: "KDC_ERR_PADATA_TYPE_NOSUPP (KDC has no support for padata type)",
    17: "KDC_ERR_TRTYPE_NOSUPP (KDC has no support for transited type)",
    18: "KDC_ERR_CLIENT_REVOKED (Clients credentials have been revoked)",
    19: "KDC_ERR_SERVICE_REVOKED (Credentials for server have been revoked)",
    20: "KDC_ERR_TGT_REVOKED (TGT has been revoked)",
    21: "KDC_ERR_CLIENT_NOTYET (Client not yet valid; try again later)",
    22: "KDC_ERR_SERVICE_NOTYET (Server not yet valid; try again later)",
    23: "KDC_ERR_KEY_EXPIRED (Password has expired; change password to reset)",
    24: "KDC_ERR_PREAUTH_FAILED (Pre-auth invalid; check password)",
    25: "KDC_ERR_PREAUTH_REQUIRED (Additional pre-authentication required)",
    26: "KDC_ERR_SERVER_NOMATCH (Requested server and ticket don't match)",
    27: "KDC_ERR_MUST_USE_USER2USER (Server principal valid for usr2usr only)",
    28: "KDC_ERR_PATH_NOT_ACCEPTED (KDC Policy rejects transited path)",
    29: "KDC_ERR_SVC_UNAVAILABLE (A service is not available)",
    31: "KRB_AP_ERR_BAD_INTEGRITY (Integrity check on decrypted field failed)",
    32: "KRB_AP_ERR_TKT_EXPIRED (Ticket expired)",
    33: "KRB_AP_ERR_TKT_NYV (Ticket not yet valid)",
    34: "KRB_AP_ERR_REPEAT (Request is a replay)",
    35: "KRB_AP_ERR_NOT_US (The ticket isn't for us)",
    36: "KRB_AP_ERR_BADMATCH (Ticket and authenticator don't match)",
    37: "KRB_AP_ERR_SKEW (Clock skew too great)",
    38: "KRB_AP_ERR_BADADDR (Incorrect net address)",
    39: "KRB_AP_ERR_BADVERSION (Protocol version mismatch)",
    40: "KRB_AP_ERR_MSG_TYPE (Invalid msg type)",
    41: "KRB_AP_ERR_MODIFIED (Message stream modified)",
    42: "KRB_AP_ERR_BADORDER (Message out of order)",
    44: "KRB_AP_ERR_BADKEYVER (Specified version of key is not available)",
    45: "KRB_AP_ERR_NOKEY (Service key not available)",
    46: "KRB_AP_ERR_MUT_FAIL (Mutual authentication failed)",
    47: "KRB_AP_ERR_BADDIRECTION (Incorrect message direction)",
    48: "KRB_AP_ERR_METHOD (Alternative authentication method required)",
    49: "KRB_AP_ERR_BADSEQ (Incorrect sequence number in message)",
    50: "KRB_AP_ERR_INAPP_CKSUM (Inappropriate type of checksum in message)",
    51: "KRB_AP_PATH_NOT_ACCEPTED (Policy rejects transited path)",
    52: "KRB_ERR_RESPONSE_TOO_BIG (Response too big for UDP; retry with TCP)",
    60: "KRB_ERR_GENERIC (Generic error; description in e-text)",
    61: "KRB_ERR_FIELD_TOOLONG (Field is too long for this implementation)",
    62: "KDC_ERROR_CLIENT_NOT_TRUSTED (Reserved for PKINIT)",
    63: "KDC_ERROR_KDC_NOT_TRUSTED (Reserved for PKINIT)",
    64: "KDC_ERROR_INVALID_SIG (Reserved for PKINIT)",
    65: "KDC_ERR_KEY_TOO_WEAK (Reserved for PKINIT)",
    66: "KDC_ERR_CERTIFICATE_MISMATCH (Reserved for PKINIT)",
    67: "KRB_AP_ERR_NO_TGT (No TGT available to validate USER-TO-USER)",
    68: "KDC_ERR_WRONG_REALM (Reserved for future use)",
    69: "KRB_AP_ERR_USER_TO_USER_REQUIRED (Ticket must be for USER-TO-USER)",
    70: "KDC_ERR_CANT_VERIFY_CERTIFICATE (Reserved for PKINIT)",
    71: "KDC_ERR_INVALID_CERTIFICATE (Reserved for PKINIT)",
    72: "KDC_ERR_REVOKED_CERTIFICATE (Reserved for PKINIT)",
    73: "KDC_ERR_REVOCATION_STATUS_UNKNOWN (Reserved for PKINIT)",
    74: "KDC_ERR_REVOCATION_STATUS_UNAVAILABLE (Reserved for PKINIT)",
    75: "KDC_ERR_CLIENT_NAME_MISMATCH (Reserved for PKINIT)",
    76: "KDC_ERR_KDC_NAME_MISMATCH (Reserved for PKINIT)",
    77: (
        "KDC_ERR_INCONSISTENT_KEY_PURPOSE "
        "(Certificate cannot be used for PKINIT client authentication)"),
    78: (
        "KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED "
        "(Digest algorithm for the public key is not acceptable)"),
    79: "KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED (The paChksum field is missing)",
    80: (
        "KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED "
        "(Digest algorithm used by id-pkinit-authData is not acceptable)"),
    81: (
        "KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED "
        "(The KDC does not support public key encryption delivery)"),
    90: "KDC_ERR_PREAUTH_EXPIRED (Pre-authentication has expired)",
    91: "KDC_ERR_MORE_PREAUTH_DATA_REQUIRED (Additional pre-auth required)",
    92: (
        "KDC_ERR_PREAUTH_BAD_AUTHENTICATION_SET "
        "(KDC cannot accommodate requested pre-authentication element)"),
    93: "KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS (Unknown critical option)"
}


def parse_krb_error(data: bytes):
    if data[0] != 0x7e:
        return

    code = -1
    pos = 2 if data[1] < 128 else 2 + (data[1] & 0x7f)
    pos += 2 if data[pos+1] < 128 else 2 + (data[pos+1] & 0x7f)

    while pos < len(data):
        tag = data[pos]
        length = data[pos+1]
        if tag == 0xa6:
            code = data[pos + 4]
            if code == KDC_ERR_PREAUTH_REQUIRED:
                return
            break
        pos += 2 + length

    raise KerberosErr(
        KRB_ERRORS.get(code, f"Unknown Kerberos Error: {code}")
    )
