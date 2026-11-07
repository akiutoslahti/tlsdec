from enum import Enum
from typing import NamedTuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tlsdec.errors import DecryptError
from tlsdec.handshake import HandshakeType, handshake_walker
from tlsdec.kdf import TrafficKeys
from tlsdec.record import TlsContentType, TlsRecord

IV_LEN = 12
SEQNO_LEN = 8

AESGCM_TAG_LEN = 16
DECRYPT_MIN_LEN = AESGCM_TAG_LEN + 1

TLS_ALERT_LEN = 2
TLS_ALERT_DESCRIPTION_OFFS = 1
TLS_ALERT_CLOSE_NOTIFY = 0


def get_nonce(iv: bytes, seqno: int) -> bytes:
    if len(iv) != IV_LEN:
        raise DecryptError(f"Invalid length IV (got {len(iv)}, expected {IV_LEN} bytes)")

    if seqno < 0:
        raise DecryptError(f"Invalid sequence number {seqno}; must be non-negative")

    try:
        seqno_padded = (IV_LEN - SEQNO_LEN) * b"\x00" + seqno.to_bytes(SEQNO_LEN, "big")
    except OverflowError as err:
        raise DecryptError(f"Invalid sequence number {seqno}; must fit into {SEQNO_LEN} bytes") from err

    return bytes(a ^ b for a, b in zip(seqno_padded, iv, strict=True))


class TlsInnerPlaintext(NamedTuple):
    content_type: TlsContentType
    content: bytes


def get_tls_inner_plaintext(data: bytes) -> TlsInnerPlaintext:
    stripped_data = data.rstrip(b"\x00")
    if len(stripped_data) == 0:
        raise DecryptError("Invalid data; no non-zero byte found")

    content_type_byte = stripped_data[-1]

    try:
        content_type = TlsContentType(content_type_byte)
    except ValueError as err:
        raise DecryptError(f"Unknown content type {content_type_byte}") from err

    if content_type == TlsContentType.CHANGE_CIPHER_SPEC:
        raise DecryptError(f"Invalid content type {content_type.name} for TlsInnerPlaintext")

    return TlsInnerPlaintext(content_type=content_type, content=stripped_data[0:-1])


def tls_decrypt_record(record: TlsRecord, key: bytes, iv: bytes, seqno: int) -> TlsInnerPlaintext:
    if record.content_type != TlsContentType.APPLICATION_DATA:
        raise DecryptError(
            f"Wrong outer type; got {record.content_type.name}, expected {TlsContentType.APPLICATION_DATA.name}"
        )

    if len(record.body) < DECRYPT_MIN_LEN:
        raise DecryptError(f"TLS record body too short; got {len(record.body)} of minimum of {DECRYPT_MIN_LEN}")

    nonce = get_nonce(iv, seqno)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, record.body, record.header)
    except InvalidTag as err:
        raise DecryptError(f"Invalid tag; record index: {record.idx}, sequence number: {seqno}") from err

    return get_tls_inner_plaintext(plaintext)


class TlsKeyType(Enum):
    HANDSHAKE = 1
    APPLICATION = 2


class TlsDecryptResult(NamedTuple):
    record_index: int
    outer_type: TlsContentType
    outer_length: int
    decrypt_key: TlsKeyType | None
    record_sequence_number: int | None
    inner_type: TlsContentType | None
    inner_content: bytes | None
    handshake_types: list[HandshakeType]


def tls_decrypt_direction(
    records: list[TlsRecord], handshake_keys: TrafficKeys, app_keys: TrafficKeys
) -> list[TlsDecryptResult]:
    closed = False
    active_key_type = TlsKeyType.HANDSHAKE
    sequence_number = 0
    handshake_buffer = b""
    output = []

    for outer in records:
        if closed:
            break

        # Not protected (20, 21, 22)
        if outer.content_type in [TlsContentType.CHANGE_CIPHER_SPEC, TlsContentType.ALERT, TlsContentType.HANDSHAKE]:
            output.append(
                TlsDecryptResult(
                    record_index=outer.idx,
                    outer_type=outer.content_type,
                    outer_length=outer.length,
                    decrypt_key=None,
                    record_sequence_number=None,
                    inner_type=None,
                    inner_content=None,
                    handshake_types=[],
                )
            )
            continue

        # Anything else than 23
        if outer.content_type != TlsContentType.APPLICATION_DATA:
            raise DecryptError(f"[record {outer.idx}] Unknown content type {outer.content_type.name}")

        # decrypt
        keys = handshake_keys if active_key_type == TlsKeyType.HANDSHAKE else app_keys
        inner = tls_decrypt_record(outer, keys.key, keys.iv, sequence_number)

        # book-keep
        out_key_type = active_key_type
        out_sequence_number = sequence_number
        sequence_number += 1
        handshake_types = []

        # inner types
        if inner.content_type == TlsContentType.HANDSHAKE:
            handshake_buffer += inner.content
            walker_res = handshake_walker(handshake_buffer)
            handshake_types = [msg.type for msg in walker_res.complete_messages]
            handshake_buffer = walker_res.left_over_data

        if inner.content_type == TlsContentType.APPLICATION_DATA and active_key_type != TlsKeyType.APPLICATION:
            raise DecryptError(f"[record {outer.idx}] 0-RTT data is not supported")

        if inner.content_type == TlsContentType.ALERT:
            if len(inner.content) != TLS_ALERT_LEN:
                raise DecryptError(
                    f"[record {outer.idx}] Invalid length for TLS ALERT; got {len(inner.content)}, expected {TLS_ALERT_LEN}"
                )

            if inner.content[TLS_ALERT_DESCRIPTION_OFFS] == TLS_ALERT_CLOSE_NOTIFY:
                closed = True

        # output
        output.append(
            TlsDecryptResult(
                record_index=outer.idx,
                outer_type=outer.content_type,
                outer_length=outer.length,
                decrypt_key=out_key_type,
                record_sequence_number=out_sequence_number,
                inner_type=inner.content_type,
                inner_content=inner.content,
                handshake_types=handshake_types,
            )
        )

        if HandshakeType.FINISHED in handshake_types and active_key_type == TlsKeyType.HANDSHAKE:
            if len(handshake_buffer) != 0:
                raise DecryptError(f"[record {outer.idx}] non-empy handshake buffer when processing FINISHED")
            active_key_type = TlsKeyType.APPLICATION
            sequence_number = 0

    if len(handshake_buffer) != 0:
        raise DecryptError("non-empty handshake buffer after processing all records")

    return output
