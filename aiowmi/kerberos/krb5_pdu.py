import datetime
import struct
from .asn1 import asn1_len, asn1_seq, asn1_tag, asn1_int, asn1_gt, asn1_ostr
from .tools import encrypt_kerberos_rc4, encrypt_kerberos_aes_cts
from ..dcom_const import NDR_TransferSyntaxIdentifier
from ..rpc.const import RPC_C_AUTHN_GSS_NEGOTIATE


def get_neg_token(service_session_key: bytes, seq_number: int, etype: int):
    now = datetime.datetime.now(datetime.timezone.utc)
    timestamp = now.strftime('%Y%m%d%H%M%SZ').encode('ascii')
    cusec = now.microsecond

    enc_ap_rep_body = (
        asn1_tag(0, asn1_gt(timestamp)) +   # [0] ctime
        asn1_tag(1, asn1_int(cusec)) +      # [1] cusec
        asn1_tag(3, asn1_int(seq_number))   # [3] seq-number
    )

    inner_seq = b'\x30' + asn1_len(enc_ap_rep_body) + enc_ap_rep_body
    plaintext = b'\x7b' + asn1_len(inner_seq) + inner_seq

    if etype in [17, 18]:  # AES-128 / AES-256
        enc_data = encrypt_kerberos_aes_cts(service_session_key, 12, plaintext)
        current_etype = etype
    else:   # RC4 (23)
        enc_data = encrypt_kerberos_rc4(service_session_key, 12, plaintext)
        current_etype = 23

    enc_part_content = (
        asn1_tag(0, asn1_int(current_etype)) +
        asn1_tag(2, asn1_ostr(enc_data))
    )

    ap_rep_body = (
        asn1_tag(0, asn1_int(5)) +                   # pvno
        asn1_tag(1, asn1_int(15)) +                  # msg-type 15 (AP-REP)
        asn1_tag(2, b'\x30' + asn1_len(enc_part_content) + enc_part_content)
    )

    ap_rep_wrap = b'\x30' + asn1_len(ap_rep_body) + ap_rep_body
    ap_rep_full = b'\x6f' + asn1_len(ap_rep_wrap) + ap_rep_wrap

    # MechToken [2] -> Octet String -> AP-REP
    resp_token = asn1_tag(2, asn1_ostr(ap_rep_full))

    # NegTokenResp [1] -> Sequence -> MechToken
    auth_neg_token = asn1_tag(1, b'\x30' + asn1_len(resp_token) + resp_token)

    return auth_neg_token


def build_alter_context(iid: bytes,
                        call_id: int,
                        auth_level: int,
                        context_id: int,
                        neg_token: bytes):
    ndr_ts = NDR_TransferSyntaxIdentifier

    sec_trailer = struct.pack('<BBBB',
                              RPC_C_AUTHN_GSS_NEGOTIATE,
                              auth_level,
                              0x00, 0x00) + struct.pack('<I', context_id)

    ctx_body = (
        b'\x00\x00\x00\x00' +       # Padding
        b'\x01\x00\x00\x00' +       # NumCtxItems: 1
        b'\x00\x00' +               # Context ID: 0
        b'\x01\x00' +               # NumTransItems: 1
        iid +                       # IID (20 bytes incl version)
        ndr_ts +                    # Syntax (20 bytes)
        b'\x00\x00\x01\x00' +       # Impacket indicator / marker
        iid +                       # IID repeat (20 bytes)
        ndr_ts                      # Syntax repeat (20 bytes)
    )

    auth_len = len(neg_token)
    frag_len = 124 + auth_len

    header = (
        b'\x05\x00' +               # RPC Version 5.0
        b'\x0e' +                   # PDU Type: Alter Context
        b'\x03' +                   # Flags: First + Last
        b'\x10\x00\x00\x00' +       # Data Representation
        struct.pack('<H', frag_len) +
        struct.pack('<H', auth_len) +
        struct.pack('<I', call_id) +
        b'\xb8\x10\xb8\x10'         # Max Xmit/Recv (4280)
    )

    return header + ctx_body + sec_trailer + neg_token
