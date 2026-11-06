from enum import IntEnum
from typing import NamedTuple

from tlsdec.errors import HandshakeError
from tlsdec.kdf import CipherSuite

HANDSHAKE_HDR_LEN = 4
HANDSHAKE_MSG_TYPE_OFFS = 0
HANDSHAKE_LENGTH_OFFS = 1
HANDSHAKE_LENGTH_LEN = 3

HELLO_RANDOM_OFFS = 2
HELLO_RANDOM_LEN = 32

SERVER_HELLO_LEGACY_SESSION_ID_ECHO_OFFS = 34
SERVER_HELLO_LEGACY_SESSION_ID_ECHO_LEN = 1
SERVER_HELLO_CIPHER_SUITE_LEN = 2

HELLO_RETRY_REQUEST_RANDOM_MAGIC = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")


class HandshakeType(IntEnum):
    ClientHello = 1
    ServerHello = 2


class HandshakeHeader(NamedTuple):
    type: HandshakeType
    body: bytes
    bytes_consumed: int


def parse_handshake(data: bytes) -> HandshakeHeader:
    if len(data) < HANDSHAKE_HDR_LEN:
        raise HandshakeError(f"Can't extract Handshake header; got {len(data)} of {HANDSHAKE_HDR_LEN} bytes")

    msg_type = data[HANDSHAKE_MSG_TYPE_OFFS]
    length = int.from_bytes(data[HANDSHAKE_LENGTH_OFFS : HANDSHAKE_LENGTH_OFFS + HANDSHAKE_LENGTH_LEN], "big")

    try:
        handshake_type = HandshakeType(msg_type)
    except ValueError as err:
        raise HandshakeError(f"Unknown Handshake type {msg_type}") from err

    if len(data) - HANDSHAKE_HDR_LEN < length:
        raise HandshakeError(f"Can't extract Handshake body; got {len(data) - HANDSHAKE_HDR_LEN} of {length} bytes")

    return HandshakeHeader(
        type=handshake_type,
        body=data[HANDSHAKE_HDR_LEN : HANDSHAKE_HDR_LEN + length],
        bytes_consumed=HANDSHAKE_HDR_LEN + length,
    )


def check_msg_type(handshake: HandshakeHeader, handshake_type: HandshakeType) -> None:
    if handshake.type != handshake_type:
        raise HandshakeError(f"Invalid Handshake type (got {handshake.type.name}, expected {handshake_type.name})")


def parse_client_hello(handshake: HandshakeHeader) -> bytes:
    check_msg_type(handshake, HandshakeType.ClientHello)

    data = handshake.body
    if len(data) < HELLO_RANDOM_OFFS + HELLO_RANDOM_LEN:
        raise HandshakeError(
            f"Can't extract random from ClientHello; got {len(data)} of {HELLO_RANDOM_OFFS + HELLO_RANDOM_LEN} bytes"
        )

    return data[HELLO_RANDOM_OFFS : HELLO_RANDOM_OFFS + HELLO_RANDOM_LEN]


def parse_server_hello(handshake: HandshakeHeader) -> CipherSuite:
    check_msg_type(handshake, HandshakeType.ServerHello)

    data = handshake.body
    if len(data) < SERVER_HELLO_LEGACY_SESSION_ID_ECHO_OFFS + SERVER_HELLO_LEGACY_SESSION_ID_ECHO_LEN:
        raise HandshakeError(
            f"Can't extract legacy session id echo length from ServerHello; got {len(data)} of {SERVER_HELLO_LEGACY_SESSION_ID_ECHO_OFFS + SERVER_HELLO_LEGACY_SESSION_ID_ECHO_LEN} bytes"
        )

    random = data[HELLO_RANDOM_OFFS : HELLO_RANDOM_OFFS + HELLO_RANDOM_LEN]
    if random == HELLO_RETRY_REQUEST_RANDOM_MAGIC:
        raise HandshakeError("ServerHello rejected as HelloRetryRequest")

    legacy_session_id_echo_len = data[SERVER_HELLO_LEGACY_SESSION_ID_ECHO_OFFS]
    cipher_suite_start = (
        SERVER_HELLO_LEGACY_SESSION_ID_ECHO_OFFS + SERVER_HELLO_LEGACY_SESSION_ID_ECHO_LEN + legacy_session_id_echo_len
    )
    cipher_suite_end = cipher_suite_start + SERVER_HELLO_CIPHER_SUITE_LEN

    if len(data) < cipher_suite_end:
        raise HandshakeError(
            f"Can't extract Cipher Suite from ServerHello; got {len(data)} of {cipher_suite_end} bytes"
        )

    cipher_suite_raw = int.from_bytes(data[cipher_suite_start:cipher_suite_end], "big")
    try:
        cipher_suite = CipherSuite(cipher_suite_raw)
    except ValueError as err:
        raise HandshakeError(f"Unknown Cipher Suite {hex(cipher_suite_raw)}") from err

    return cipher_suite
