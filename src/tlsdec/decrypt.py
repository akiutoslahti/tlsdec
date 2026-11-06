from typing import NamedTuple

from tlsdec.errors import DecryptError
from tlsdec.record import TlsContentType

IV_LEN = 12
SEQNO_LEN = 8


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
