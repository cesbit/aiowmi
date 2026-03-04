import struct
from datetime import datetime, timezone
from .asn1 import asn1_len
from .tools import encrypt_kerberos_rc4



def wrap_gss_kerberos(ap_req_bytes):
    OID_KERBEROS_V5          = b'\x2a\x86\x48\x86\xf7\x12\x01\x02\x02'
    OID_MS_LEGACY_KERBEROS   = b'\x2a\x86\x48\x82\xf7\x12\x01\x02\x02'

    mech_list = b'\x30\x0b\x06\t' + OID_MS_LEGACY_KERBEROS
    mech_types_wrapper = b'\xa0\x0d' + mech_list

    inner_token = b'\x06\t\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x01\x00' + ap_req_bytes
    gss_api_token = b'\x60' + asn1_len(len(inner_token)) + inner_token

    mech_token_octet = b'\x04' + asn1_len(len(gss_api_token)) + gss_api_token
    mech_token_wrapper = b'\xa2' + asn1_len(len(mech_token_octet)) + mech_token_octet

    neg_token_content = mech_types_wrapper + mech_token_wrapper
    neg_token_sequence = b'\x30' + asn1_len(len(neg_token_content)) + neg_token_content

    spnego_oid = b'\x06\x06\x2b\x06\x01\x05\x05\x02'

    neg_token_init_wrapper = b'\xa0' + asn1_len(len(neg_token_sequence)) + neg_token_sequence

    final_auth_value_inner = spnego_oid + neg_token_init_wrapper
    final_auth_value = b'\x60' + asn1_len(len(final_auth_value_inner)) + final_auth_value_inner

    return final_auth_value


def build_ap_req(username: str, domain: str, ticket: bytes, service_session_key: bytes) -> bytes:
    now = datetime.now(timezone.utc)
    timestamp = now.strftime('%Y%m%d%H%M%SZ').encode('ascii')

    gss_data = (
        b'\x10\x00\x00\x00' +
        b'\x00' * 16 +
        b'\x3e\x10\x00\x00'
    )

    cksum_asn1 = (
        b'\xa3\x25' +
        b'\x30\x23' +
        b'\xa0\x05' +
        b'\x02\x03\x00\x80\x03' +
        b'\xa1\x1a' +
        b'\x04\x18' +
        gss_data
    )

    username_bytes = username.encode()
    cname_string_seq = (
        b'\x30' + asn1_len(len(username_bytes) + 2) +
        b'\x1b' + asn1_len(len(username_bytes)) + username_bytes
    )
    cname_payload = (
        b'\xa0\x03\x02\x01\x01' +
        b'\xa1' + asn1_len(len(cname_string_seq)) + cname_string_seq
    )
    cname_total = b'\x30' + asn1_len(len(cname_payload)) + cname_payload
    cname_asn1 = b'\xa2' + asn1_len(len(cname_total)) + cname_total

    realm_str = domain.encode()
    realm_asn1 = b'\x1b' + asn1_len(len(realm_str)) + realm_str
    crealm_asn1  = b'\xa1' + asn1_len(len(realm_asn1)) + realm_asn1

    # The following all all checked and 100% equal:
    # crealm_asn1 +
    # cname_asn1 +
    # cksum_asn1 +

    auth_body = (
        b'\xa0\x03\x02\x01\x05' +
        crealm_asn1 +
        cname_asn1 +
        cksum_asn1 +
        b'\xa4\x05\x02\x03\x03\x7b\xb7' +
        b'\xa5\x11\x18\x0f' + timestamp +
        b'\xa7\x03\x02\x01\x00'
    )

    inner_seq = b'\x30\x81' + struct.pack('B', len(auth_body)) + auth_body
    authenticator_asn1 = b'\x62\x81' + struct.pack('B', len(inner_seq)) + inner_seq

    encrypted_authenticator = encrypt_kerberos_rc4(service_session_key, 11, authenticator_asn1)

    # print(f'[D] ticket out lib: {ticket.hex()}')
    # print(f'[I] ticket IMPACKET: a3820557618205533082054fa003020105a1181b164c41422e544553542d544543484e4f4c4f47592e4e4ca23c303aa003020102a13330311b04686f73741b29646f6d61696e636f6e74726f6c6c657230312e6c61622e746573742d746563686e6f6c6f67792e6e6ca38204ee308204eaa003020112a103020135a28204dc048204d83420a7b6dce9cc4087c3d226ee335636868792308b112c62b273b9a8c87004cecf9f8fb1e3b3e90f8770584a1741d74fa5dc2ea8a308f329ac08b46fd17485cafe660ec8bdf793093648f2b7b64c2e695e0cf905ba6003a76f02a3faba314f10a741d46bb6a7dbbf3a20fe90a40deb3c826966a86e3ff398e5fa755efb3a0f485c892fcda4a3e968dfd538519ffc2b7cb9170ba98558dd16fae6a684fbd0107e055792cb6192b03a7cebc123bee490d7c0d33d1b40d16e6970ade252bbdc720e07730e9de84b0e79cfb94120487988c97be5c6325f8c3c6e42601a005ac4793de32de2392924bf0617e4967471322bf03f4939306bf9104956e91a400b82e3d9c66434c81e530c26f4c9146f6e06f9897dd0d86de977fc82974570e083aae6ebc7d8b86e1588e934be604478c3fbe34699536730121bddf078d01837ad9cd8aaaa639b1ececb9ecbcb05ce2f8a7ad723e4a06c1f5673fb089b6ea7a9b376f2acc495103db002ab58451dcaf76198e2ed515504f50cfcc67103c9a686e415d64f7b3e1b214f47fcf8d6123ecb8fc34379b1c0ce3d005aa071b54cab414102a3767d3fab2bad0d7d28e6a3e2f099ac958f6346fa61e78965b9550912a9f4d80ab9c59d2f8b687e47d16918b592e30d291f99f827551781bb9cd67d1438830f8cc6c99c131faf708f8fc83a4cc5285bf512c5fa398dc5def8f1842a43086a49006409157b3ac1b66e2dadddfeaf52c7ebfe1ad746a48b920be5ebb876e0b7b1d563a863969e56a35e9fe394b6d6a8bb453f6427fe408e76505ca70048799e1cb1c9a995a93518298fab04237433d7f7fc44b89cda39c1288bdaddd5716c6c99eafa92e2a7e90b04600c7b762a87da9b9623c061797a3472c7ff0c6f28ffcf48d04ba484095c3379aa3042356e158d5890bc8afb2114504de649b1719844ee8311e618c23ef12528c4dfe739d11c13109f8529808ca1c0a25acffff2ae35e13fbc745bff195181413afd05b804bbc4c6e60e370ad06696c6d633c77cb8248806035848cbb051c59022f5292542849b2c8d4e29df79950b1809aafea72a524059adc4445c1c119442257d2a293781153aee9935b5da952d9339d08154de97b4db6cf2583be50de38e209f1cd91cbb86e8f7ef34f7f0729dc3a998421768623d6280fd44b56061e98859a78e0179c8b25ca9bb84dad68d7008d0c93bf74b1c5e2f782272a66f44bdf263f167b740a2192c09f2be3640fc33a31120b4db77a05fec6339a5b7a463e74f4ffa908dfb65fae3eff75174e86d29e92d130f0c00b253d42b7fdcc6f2c09197ae6d1e28be58ba9082a04a9c7e770f2a9864b1c066a2584e1d96e2b6bbcff03ad96e0b1a0a4d4929d7268396287decbc9e53cdf492c98bd0baf465b9a8be1c4221db2946dde9dfc75594862816da88ee66289a7e09fad3f60363002ec856523dc347ae5d325b1ebca30e766d400f906ac5b285eb1369e7bf1b776cddc1dee550efce3dc75f8aeb56a1c887aa173f74e650263c309c642e70e115e2dc526c08ae0c52b6bf1c4eabf7f040c291245354eedca386be5bfbd3c084dc594cc17bc4741a4e12173a0b5131d8a2b9c657fff4faa80e7ff1c2f7d95e90a81f577aa577ad0e55f6dd372f8767a2c4a445a24685d498a3ac32fe675b3e12bd6d1f6d95ef14b2817b1911358bb12e52453afadf5075bd90cb26248730aaaccc8f9d96e71b188992c45be7e09006fe26016c469db90e4612')
    # print(f'[D] encrypted_authenticator (LEN: {len(encrypted_authenticator)}) HEX: {encrypted_authenticator.hex()}')
    # print(f'[I] encrypted_authenticator IMPACKET (LEN: 159) HEX: b15d434808309ed7b4f5c5d24105a8a4223be9d634de5f42665d4456c8c6335486c7eddd67ae9c15f9a2d682f95de3070dc8254233513f93c8216c2400b7329cccc10c41ba872944f7a3e4ccd48c7d154da3c92752f908524401a52a2a3028b8a13f8c2c1dd9260119d5323357ba1044330aa59fe559562ece294517c791e72d378a72688b870d02d41b5f60c926d8bad9020c5a77418c4bc643fa49593430')

    etype = 18 if len(service_session_key) == 32 else 17

    if ticket.startswith(b'\xa5'):
        ticket_start = ticket.find(b'\x61')
        actual_ticket = ticket[ticket_start:]
    else:
        actual_ticket = ticket

    etype_asn1 = b'\xa0\x03\x02\x01' + bytes([etype])
    cipher_inner = b'\x04' + asn1_len(len(encrypted_authenticator)) + encrypted_authenticator
    cipher_asn1 = b'\xa2' + asn1_len(len(cipher_inner)) + cipher_inner

    inner_body = etype_asn1 + cipher_asn1
    enc_part = (
        b'\xa4' + asn1_len(len(inner_body) + 2) +
        b'\x30' + asn1_len(len(inner_body)) + inner_body
    )

    ap_req_body = (
        b'\xa0\x03\x02\x01\x05' +
        b'\xa1\x03\x02\x01\x0e' +
        b'\xa2\x07\x03\x05\x00\x20\x00\x00\x00' +
        b'\xa3' + asn1_len(len(actual_ticket)) + actual_ticket +
        enc_part
    )

    final_ap_req = (
        b'\x6e\x82' + struct.pack('>H', len(ap_req_body) + 4) +
        b'\x30\x82' + struct.pack('>H', len(ap_req_body)) +
        ap_req_body
    )

    # print(f'[D] ap_req (LEN: {len(final_ap_req)}) HEX: {final_ap_req.hex()}')
    # print(f'[I] ap_req IMPACKET (LEN: 1574) HEX: 6e8206223082061ea003020105a10302010ea20703050020000000a3820557618205533082054fa003020105a1181b164c41422e544553542d544543484e4f4c4f47592e4e4ca23c303aa003020102a13330311b04686f73741b29646f6d61696e636f6e74726f6c6c657230312e6c61622e746573742d746563686e6f6c6f67792e6e6ca38204ee308204eaa003020112a103020135a28204dc048204d83420a7b6dce9cc4087c3d226ee335636868792308b112c62b273b9a8c87004cecf9f8fb1e3b3e90f8770584a1741d74fa5dc2ea8a308f329ac08b46fd17485cafe660ec8bdf793093648f2b7b64c2e695e0cf905ba6003a76f02a3faba314f10a741d46bb6a7dbbf3a20fe90a40deb3c826966a86e3ff398e5fa755efb3a0f485c892fcda4a3e968dfd538519ffc2b7cb9170ba98558dd16fae6a684fbd0107e055792cb6192b03a7cebc123bee490d7c0d33d1b40d16e6970ade252bbdc720e07730e9de84b0e79cfb94120487988c97be5c6325f8c3c6e42601a005ac4793de32de2392924bf0617e4967471322bf03f4939306bf9104956e91a400b82e3d9c66434c81e530c26f4c9146f6e06f9897dd0d86de977fc82974570e083aae6ebc7d8b86e1588e934be604478c3fbe34699536730121bddf078d01837ad9cd8aaaa639b1ececb9ecbcb05ce2f8a7ad723e4a06c1f5673fb089b6ea7a9b376f2acc495103db002ab58451dcaf76198e2ed515504f50cfcc67103c9a686e415d64f7b3e1b214f47fcf8d6123ecb8fc34379b1c0ce3d005aa071b54cab414102a3767d3fab2bad0d7d28e6a3e2f099ac958f6346fa61e78965b9550912a9f4d80ab9c59d2f8b687e47d16918b592e30d291f99f827551781bb9cd67d1438830f8cc6c99c131faf708f8fc83a4cc5285bf512c5fa398dc5def8f1842a43086a49006409157b3ac1b66e2dadddfeaf52c7ebfe1ad746a48b920be5ebb876e0b7b1d563a863969e56a35e9fe394b6d6a8bb453f6427fe408e76505ca70048799e1cb1c9a995a93518298fab04237433d7f7fc44b89cda39c1288bdaddd5716c6c99eafa92e2a7e90b04600c7b762a87da9b9623c061797a3472c7ff0c6f28ffcf48d04ba484095c3379aa3042356e158d5890bc8afb2114504de649b1719844ee8311e618c23ef12528c4dfe739d11c13109f8529808ca1c0a25acffff2ae35e13fbc745bff195181413afd05b804bbc4c6e60e370ad06696c6d633c77cb8248806035848cbb051c59022f5292542849b2c8d4e29df79950b1809aafea72a524059adc4445c1c119442257d2a293781153aee9935b5da952d9339d08154de97b4db6cf2583be50de38e209f1cd91cbb86e8f7ef34f7f0729dc3a998421768623d6280fd44b56061e98859a78e0179c8b25ca9bb84dad68d7008d0c93bf74b1c5e2f782272a66f44bdf263f167b740a2192c09f2be3640fc33a31120b4db77a05fec6339a5b7a463e74f4ffa908dfb65fae3eff75174e86d29e92d130f0c00b253d42b7fdcc6f2c09197ae6d1e28be58ba9082a04a9c7e770f2a9864b1c066a2584e1d96e2b6bbcff03ad96e0b1a0a4d4929d7268396287decbc9e53cdf492c98bd0baf465b9a8be1c4221db2946dde9dfc75594862816da88ee66289a7e09fad3f60363002ec856523dc347ae5d325b1ebca30e766d400f906ac5b285eb1369e7bf1b776cddc1dee550efce3dc75f8aeb56a1c887aa173f74e650263c309c642e70e115e2dc526c08ae0c52b6bf1c4eabf7f040c291245354eedca386be5bfbd3c084dc594cc17bc4741a4e12173a0b5131d8a2b9c657fff4faa80e7ff1c2f7d95e90a81f577aa577ad0e55f6dd372f8767a2c4a445a24685d498a3ac32fe675b3e12bd6d1f6d95ef14b2817b1911358bb12e52453afadf5075bd90cb26248730aaaccc8f9d96e71b188992c45be7e09006fe26016c469db90e4612a481ad3081aaa003020117a281a204819fb15d434808309ed7b4f5c5d24105a8a4223be9d634de5f42665d4456c8c6335486c7eddd67ae9c15f9a2d682f95de3070dc8254233513f93c8216c2400b7329cccc10c41ba872944f7a3e4ccd48c7d154da3c92752f908524401a52a2a3028b8a13f8c2c1dd9260119d5323357ba1044330aa59fe559562ece294517c791e72d378a72688b870d02d41b5f60c926d8bad9020c5a77418c4bc643fa49593430')
    # assert 0

    return final_ap_req
