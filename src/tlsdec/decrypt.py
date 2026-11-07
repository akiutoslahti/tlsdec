from typing import NamedTuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tlsdec.errors import DecryptError
from tlsdec.record import TlsContentType, TlsRecord

IV_LEN = 12
SEQNO_LEN = 8

AESGCM_TAG_LEN = 16
DECRYPT_MIN_LEN = AESGCM_TAG_LEN + 1


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
