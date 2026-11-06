import struct
from enum import IntEnum
from typing import NamedTuple

from tlsdec.errors import RecordError

TLS_HEADER_LEN = 5


class TlsContentType(IntEnum):
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23


TLS_CIPHERTEXT_MAX = 2**14 + 256


class TlsRecord(NamedTuple):
    idx: int
    offset: int
    header: bytes
    content_type: TlsContentType
    version: int
    length: int
    body: bytes


def record_split(tcp_stream: bytes) -> list[TlsRecord]:
    records = []
    idx = 0
    offset = 0
    while offset < len(tcp_stream):
        if len(tcp_stream) - offset < TLS_HEADER_LEN:
            raise RecordError(
                f"[index {idx}, offset {offset}] Can't extract TLS record header; truncated (got {len(tcp_stream) - offset} of {TLS_HEADER_LEN} bytes)"
            )

        (content_type, legacy_record_version, length) = struct.unpack_from("!BHH", tcp_stream, offset)

        try:
            content_type_enum = TlsContentType(content_type)
        except ValueError as err:
            raise RecordError(f"[index {idx}, offset {offset}] Unknown content type {content_type}") from err

        if length > TLS_CIPHERTEXT_MAX:
            raise RecordError(
                f"[index {idx}, offset {offset}] Invalid length (got {length}, expected maximum of {TLS_CIPHERTEXT_MAX} bytes)"
            )

        if len(tcp_stream) - offset - TLS_HEADER_LEN < length:
            raise RecordError(
                f"[index {idx}, offset {offset}] Can't extract TLS record body; truncated (got {len(tcp_stream) - offset - TLS_HEADER_LEN} of {length} bytes)"
            )

        body_start = offset + TLS_HEADER_LEN
        body_end = body_start + length
        records.append(
            TlsRecord(
                idx=idx,
                offset=offset,
                header=tcp_stream[offset : offset + TLS_HEADER_LEN],
                content_type=content_type_enum,
                version=legacy_record_version,
                length=length,
                body=tcp_stream[body_start:body_end],
            )
        )
        idx += 1
        offset += TLS_HEADER_LEN + length
    return records
