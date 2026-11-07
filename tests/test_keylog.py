import pytest
import testconf

from tlsdec.errors import KeylogError
from tlsdec.keylog import keylog_parse

CLIENT_HANDSHAKE = bytes.fromhex("cc9d8429b1171f6fd7cd01b6a72a41e3f3f0339c990480e187b5f053dd552664")
CLIENT_APP = bytes.fromhex("421089764b86d79ded11e66445680c529f1b46a0fb871af1f892fcb43b365e57")
SERVER_HANDSHAKE = bytes.fromhex("b23c9cf46146194cb6532e1bc6918df41e711cb87f72c8f67de524d76bec5c63")
SERVER_APP = bytes.fromhex("42260b3e3dc391b0747cdc218f97459d5b886edbd0f09d53c620837db44425ec")

CLIENT_RANDOM = bytes.fromhex("b619dca6141f21841e1618eca73302a92404deed8496e0c7e04f6f8fd6673c56")


def test_keylog_parse():
    secrets = keylog_parse(testconf.PATH_KEYLOG_AES_128.read_text(), CLIENT_RANDOM)

    assert secrets.client_handshake == CLIENT_HANDSHAKE
    assert secrets.client_application == CLIENT_APP
    assert secrets.server_handshake == SERVER_HANDSHAKE
    assert secrets.server_application == SERVER_APP


def test_keylog_parse_multi():
    keylog1 = testconf.PATH_KEYLOG_AES_256.read_text()
    keylog2 = testconf.PATH_KEYLOG_AES_128.read_text()
    secrets = keylog_parse("\n".join([keylog1, keylog2]), CLIENT_RANDOM)

    assert secrets.client_handshake == CLIENT_HANDSHAKE
    assert secrets.client_application == CLIENT_APP
    assert secrets.server_handshake == SERVER_HANDSHAKE
    assert secrets.server_application == SERVER_APP


def test_keylog_parse_missing_label():
    data = "\n".join(testconf.PATH_KEYLOG_AES_128.read_text().splitlines()[:-1])
    with pytest.raises(KeylogError, match="Missing CLIENT_TRAFFIC_SECRET_0"):
        keylog_parse(data, CLIENT_RANDOM)


def test_keylog_parse_malformed_line():
    data = "\n".join(
        [
            "EXPORTER_SECRET de3fe84355018060ff50eb9722c46c8cacb1417a8cbbfb4f5028008b230fdb55 ce67dc079309bba5480aa645929f7d691f941e6df7c72dd5cf06b2e1b07964cca86766856a0110b4e9d9ac6f1b4c15f",
            testconf.PATH_KEYLOG_AES_128.read_text(),
        ]
    )
    with pytest.raises(KeylogError, match="bad secret on line 1"):
        keylog_parse(data, CLIENT_RANDOM)


def test_keylog_parse_comment_line_ignored():
    data = "\n".join([testconf.PATH_KEYLOG_AES_128.read_text(), "#comment"])
    secrets = keylog_parse(data, CLIENT_RANDOM)

    assert secrets.client_handshake == CLIENT_HANDSHAKE
    assert secrets.client_application == CLIENT_APP
    assert secrets.server_handshake == SERVER_HANDSHAKE
    assert secrets.server_application == SERVER_APP
