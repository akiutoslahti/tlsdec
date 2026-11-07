# ruff: noqa: PLR2004

from pathlib import Path

import pytest
import testconf

from tlsdec.errors import HandshakeError
from tlsdec.handshake import (
    HandshakeHeader,
    HandshakeType,
    handshake_walker,
    parse_client_hello,
    parse_handshake,
    parse_server_hello,
)
from tlsdec.kdf import CipherSuite
from tlsdec.pcap import pcap_parse
from tlsdec.record import record_split
from tlsdec.tcp import tcp_parse_frame, tcp_reassemble_flow

FAKE_BODY = bytes.fromhex(
    "020000450303dcc2262104c2be890d864612ba419ba2d98eec54e267381df38f273af52c668e207533b8e8eda82446dc754873f20fe609c379577549660bc1cbffc8995ec5b3df1302"
)
FAKE_SERVER_HELLO_BODY = FAKE_BODY[4:]
FAKE_CONSUMED_LEN = 4 + len(FAKE_SERVER_HELLO_BODY)


def records(path: Path):
    parsed_pcap = pcap_parse(path.read_bytes())
    segments = [tcp_parse_frame(frame) for frame in parsed_pcap.frames]
    flow = tcp_reassemble_flow(segments)
    client_records = record_split(flow.client_stream)
    server_records = record_split(flow.server_stream)
    return (client_records, server_records)


def records_aes128():
    return records(testconf.PATH_FIXTURE_AES_128)


def records_aes256():
    return records(testconf.PATH_FIXTURE_AES_256)


def test_parse_handshake_aes128():
    (client_records, server_records) = records_aes128()
    client_hs = parse_handshake(client_records[0].body)
    server_hs = parse_handshake(server_records[0].body)

    assert client_hs.type == HandshakeType.CLIENT_HELLO
    assert len(client_hs.body) == 508
    assert client_hs.bytes_consumed == 512

    assert server_hs.type == HandshakeType.SERVER_HELLO
    assert len(server_hs.body) == 118
    assert server_hs.bytes_consumed == 122


def test_parse_handshake_aes256():
    (client_records, server_records) = records_aes256()
    client_hs = parse_handshake(client_records[0].body)
    server_hs = parse_handshake(server_records[0].body)

    assert client_hs.type == HandshakeType.CLIENT_HELLO
    assert len(client_hs.body) == 508
    assert client_hs.bytes_consumed == 512

    assert server_hs.type == HandshakeType.SERVER_HELLO
    assert len(server_hs.body) == 118
    assert server_hs.bytes_consumed == 122


def test_parse_handshake_too_short1():
    with pytest.raises(HandshakeError, match="Can't extract Handshake header"):
        parse_handshake(FAKE_BODY[:3])


def test_parse_handshake_too_short2():
    with pytest.raises(HandshakeError, match="Can't extract Handshake body"):
        parse_handshake(FAKE_BODY[:-1])


def test_parse_handshake_wrong_type():
    with pytest.raises(HandshakeError, match="Unknown Handshake type"):
        parse_handshake(b"\xff" + FAKE_BODY[1:])


def test_parse_client_hello_aes128():
    (client_records, _server_records) = records_aes128()
    client_hs = parse_handshake(client_records[0].body)
    random = parse_client_hello(client_hs)

    assert random == bytes.fromhex("b619dca6141f21841e1618eca73302a92404deed8496e0c7e04f6f8fd6673c56")


def test_parse_client_hello_aes256():
    (client_records, _server_records) = records_aes256()
    client_hs = parse_handshake(client_records[0].body)
    random = parse_client_hello(client_hs)

    assert random == bytes.fromhex("de3fe84355018060ff50eb9722c46c8cacb1417a8cbbfb4f5028008b230fdb55")


def test_parse_client_hello_wrong_type():
    client_hs = HandshakeHeader(HandshakeType.SERVER_HELLO, FAKE_SERVER_HELLO_BODY, FAKE_CONSUMED_LEN)
    with pytest.raises(HandshakeError, match="Invalid Handshake type"):
        parse_client_hello(client_hs)


def test_parse_client_hello_too_short():
    client_hs = HandshakeHeader(HandshakeType.CLIENT_HELLO, FAKE_SERVER_HELLO_BODY[:33], FAKE_CONSUMED_LEN)
    with pytest.raises(HandshakeError, match="Can't extract random from CLIENT_HELLO"):
        parse_client_hello(client_hs)


def test_parse_server_hello_aes128():
    (_client_records, server_records) = records_aes128()
    server_hs = parse_handshake(server_records[0].body)
    cipher_suite = parse_server_hello(server_hs)

    assert cipher_suite == CipherSuite.TLS_AES_128_GCM_SHA256


def test_parse_server_hello_aes256():
    (_client_records, server_records) = records_aes256()
    server_hs = parse_handshake(server_records[0].body)
    cipher_suite = parse_server_hello(server_hs)

    assert cipher_suite == CipherSuite.TLS_AES_256_GCM_SHA384


def test_parse_server_hello_wrong_type():
    server_hs = HandshakeHeader(HandshakeType.CLIENT_HELLO, FAKE_SERVER_HELLO_BODY, FAKE_CONSUMED_LEN)
    with pytest.raises(HandshakeError, match="Invalid Handshake type"):
        parse_server_hello(server_hs)


def test_parse_server_hello_too_short1():
    server_hs = HandshakeHeader(HandshakeType.SERVER_HELLO, FAKE_SERVER_HELLO_BODY[:34], FAKE_CONSUMED_LEN)
    with pytest.raises(HandshakeError, match="Can't extract legacy session id"):
        parse_server_hello(server_hs)


def test_parse_server_hello_too_short2():
    server_hs = HandshakeHeader(HandshakeType.SERVER_HELLO, FAKE_SERVER_HELLO_BODY[:-1], FAKE_CONSUMED_LEN)
    with pytest.raises(HandshakeError, match="Can't extract Cipher Suite"):
        parse_server_hello(server_hs)


def test_parse_server_hello_magic_random():
    body = (
        FAKE_SERVER_HELLO_BODY[0:2]
        + bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")
        + FAKE_SERVER_HELLO_BODY[34:]
    )
    server_hs = HandshakeHeader(HandshakeType.SERVER_HELLO, body, FAKE_CONSUMED_LEN)
    with pytest.raises(HandshakeError, match="HelloRetryRequest"):
        parse_server_hello(server_hs)


def test_parse_server_hello_unknown_cipher():
    server_hs = HandshakeHeader(
        HandshakeType.SERVER_HELLO, FAKE_SERVER_HELLO_BODY[:-2] + b"\x13\x00", FAKE_CONSUMED_LEN
    )
    with pytest.raises(HandshakeError, match="Unknown Cipher"):
        parse_server_hello(server_hs)


def test_handshake_walker_two_msg():
    data = b"\x08\x00\x00\x00\x0b\x00\x00\x00"

    (completed, leftover) = handshake_walker(data)
    assert len(completed) == 2
    assert completed[0].type == HandshakeType.ENCRYPTED_EXTENSIONS
    assert completed[1].type == HandshakeType.CERTIFICATE
    assert leftover == b""


def test_handshake_walker_split():
    data1 = b"\x08\x00\x00\x00\x0b"
    data2 = b"\x00\x00\x00"

    (completed1, leftover1) = handshake_walker(data1)
    assert len(completed1) == 1
    assert completed1[0].type == HandshakeType.ENCRYPTED_EXTENSIONS
    assert leftover1 == b"\x0b"

    (completed2, leftover2) = handshake_walker(leftover1 + data2)
    assert len(completed2) == 1
    assert completed2[0].type == HandshakeType.CERTIFICATE
    assert leftover2 == b""
