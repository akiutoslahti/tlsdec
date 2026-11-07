from pathlib import Path

import pytest
import testconf

from tlsdec.decrypt import get_nonce, get_tls_inner_plaintext, tls_decrypt_record
from tlsdec.errors import DecryptError
from tlsdec.handshake import HandshakeType, parse_client_hello, parse_handshake, parse_server_hello
from tlsdec.kdf import get_traffic_keys
from tlsdec.keylog import keylog_parse
from tlsdec.pcap import pcap_parse
from tlsdec.record import TlsContentType, TlsRecord, record_split
from tlsdec.tcp import tcp_parse_frame, tcp_reassemble_flow

IV = bytes.fromhex("00112233445566778899AABB")
INNER_PLAINTEXT = bytes("lorem ipsum dolor sit amet", "utf-8")


def test_nonce():
    assert get_nonce(IV, 0) == IV
    assert get_nonce(IV, 1) == bytes.fromhex("00112233445566778899AABA")
    assert get_nonce(IV, 2**32) == bytes.fromhex("00112233445566768899AABB")
    assert get_nonce(IV, 2**64 - 1) == bytes.fromhex("00112233BBAA998877665544")


def test_nonce_negative_seqno():
    with pytest.raises(DecryptError, match="non-negative"):
        get_nonce(IV, -1)


def test_nonce_too_large_seqno():
    with pytest.raises(DecryptError, match="must fit"):
        get_nonce(IV, 2**64)


def test_nonce_invalid_iv():
    with pytest.raises(DecryptError, match="length IV"):
        get_nonce(IV + b"\x00", 0)


def test_get_tls_inner_plaintext_all_zero():
    data = 32 * b"\x00"
    with pytest.raises(DecryptError, match="no non-zero byte found"):
        get_tls_inner_plaintext(data)


def test_get_tls_inner_plaintext_unknown_content_type():
    data = 16 * b"\x00" + b"\x13" + 15 * b"\x00"
    with pytest.raises(DecryptError, match="Unknown content type"):
        get_tls_inner_plaintext(data)


def test_get_tls_inner_plaintext_no_padding():
    data = INNER_PLAINTEXT + bytes([TlsContentType.APPLICATION_DATA])
    res = get_tls_inner_plaintext(data)
    assert res.content_type == TlsContentType.APPLICATION_DATA
    assert res.content == INNER_PLAINTEXT


def test_get_tls_inner_plaintext_some_padding():
    data = INNER_PLAINTEXT + bytes([TlsContentType.APPLICATION_DATA]) + 16 * b"\x00"
    res = get_tls_inner_plaintext(data)
    assert res.content_type == TlsContentType.APPLICATION_DATA
    assert res.content == INNER_PLAINTEXT


def test_get_tls_inner_plaintext_allzero_content():
    content = 32 * b"\x00"
    data = content + bytes([TlsContentType.APPLICATION_DATA]) + 16 * b"\x00"
    res = get_tls_inner_plaintext(data)
    assert res.content_type == TlsContentType.APPLICATION_DATA
    assert res.content == content


def test_get_tls_inner_plaintext_empty_content():
    data = bytes([TlsContentType.APPLICATION_DATA]) + 16 * b"\x00"
    res = get_tls_inner_plaintext(data)
    assert res.content_type == TlsContentType.APPLICATION_DATA
    assert res.content == b""


def test_get_tls_inner_plaintext_invalid_content_type():
    data = bytes([TlsContentType.CHANGE_CIPHER_SPEC]) + 16 * b"\x00"
    with pytest.raises(DecryptError, match="Invalid content type"):
        get_tls_inner_plaintext(data)


def tls_decrypt_helper(fixture: Path, keylog: Path):
    parsed_pcap = pcap_parse(fixture.read_bytes())
    segments = [tcp_parse_frame(frame) for frame in parsed_pcap.frames]
    flow = tcp_reassemble_flow(segments)
    client_records = record_split(flow.client_stream)
    server_records = record_split(flow.server_stream)
    client_hs = parse_handshake(client_records[0].body)
    server_hs = parse_handshake(server_records[0].body)
    client_random = parse_client_hello(client_hs)
    cipher_suite = parse_server_hello(server_hs)

    secrets = keylog_parse(keylog.read_text(), client_random)

    (client_key, client_iv) = get_traffic_keys(cipher_suite, secrets.client_handshake)
    (server_key, server_iv) = get_traffic_keys(cipher_suite, secrets.server_handshake)

    return (client_records, client_key, client_iv, server_records, server_key, server_iv)


def test_tls_decrypt_record_aes128():
    (client_records, client_key, client_iv, server_records, server_key, server_iv) = tls_decrypt_helper(
        testconf.PATH_FIXTURE_AES_128, testconf.PATH_KEYLOG_AES_128
    )

    client_data = tls_decrypt_record(client_records[2], client_key, client_iv, 0)
    server_data = tls_decrypt_record(server_records[2], server_key, server_iv, 0)

    assert client_data.content_type == TlsContentType.HANDSHAKE
    assert server_data.content_type == TlsContentType.HANDSHAKE

    client_hs = parse_handshake(client_data.content)
    server_hs = parse_handshake(server_data.content)

    assert client_hs.type == HandshakeType.FINISHED
    assert client_hs.body == bytes.fromhex("70c5320f8de243df9b650da03a19a492a4774b622a182172f6df640ea94f46d0")
    assert server_hs.type == HandshakeType.ENCRYPTED_EXTENSIONS
    assert server_hs.body == bytes.fromhex("0000")


def test_tls_decrypt_record_aes256():
    (client_records, client_key, client_iv, server_records, server_key, server_iv) = tls_decrypt_helper(
        testconf.PATH_FIXTURE_AES_256, testconf.PATH_KEYLOG_AES_256
    )

    client_data = tls_decrypt_record(client_records[2], client_key, client_iv, 0)
    server_data = tls_decrypt_record(server_records[2], server_key, server_iv, 0)

    assert client_data.content_type == TlsContentType.HANDSHAKE
    assert server_data.content_type == TlsContentType.HANDSHAKE

    client_hs = parse_handshake(client_data.content)
    server_hs = parse_handshake(server_data.content)

    assert client_hs.type == HandshakeType.FINISHED
    assert client_hs.body == bytes.fromhex(
        "9028e897f09bc25a0feb77dd0cda80283ea29511f2e9394f6514969210853e4e2f182bc66eb8981a03309c7dda63f5cc"
    )
    assert server_hs.type == HandshakeType.ENCRYPTED_EXTENSIONS
    assert server_hs.body == bytes.fromhex("0000")


def test_tls_decrypt_record_tag_failure():
    (client_records, client_key, client_iv, _server_records, _server_key, _server_iv) = tls_decrypt_helper(
        testconf.PATH_FIXTURE_AES_128, testconf.PATH_KEYLOG_AES_128
    )

    with pytest.raises(DecryptError, match="Invalid tag; record index"):
        tls_decrypt_record(client_records[2], client_key, client_iv, 1)


def test_tls_decrypt_record_wrong_type():
    record = TlsRecord(0, 0, b"", TlsContentType.CHANGE_CIPHER_SPEC, 0, 0, 17 * b"\x00")

    with pytest.raises(DecryptError, match="Wrong outer type"):
        tls_decrypt_record(record, b"", b"", 0)


def test_tls_decrypt_record_too_short():
    record = TlsRecord(0, 0, b"", TlsContentType.APPLICATION_DATA, 0, 0, 16 * b"\x00")

    with pytest.raises(DecryptError, match="TLS record body too short"):
        tls_decrypt_record(record, b"", b"", 0)
