import struct
from dataclasses import dataclass
from typing import NamedTuple

from tlsdec.errors import PcapError

MAGIC_NUMBER1 = int.from_bytes(b"\xa1\xb2\xc3\xd4", "big")
MAGIC_NUMBER2 = int.from_bytes(b"\xa1\xb2\x3c\x4d", "big")

MAGIC_NUMBER_OFFSET = 0
GLOBAL_HEADER_OFFSET = 0
GLOBAL_HEADER_LEN = 24
PACKET_RECORD_HEADER_LEN = 16

LINK_TYPE_MASK = 0xFFFF
EXPECTED_LINK_TYPE = 1


class Frame(NamedTuple):
    frameno: int
    data: bytes


@dataclass
class PcapData:
    link_type: int
    frames: list[Frame]


def pcap_parse(data: bytes) -> PcapData:
    if len(data) < GLOBAL_HEADER_LEN:
        raise PcapError(f"Can't extract global header; truncated pcap (got {len(data)} of {GLOBAL_HEADER_LEN} bytes)")

    magic_number_le = struct.unpack_from("<L", data, MAGIC_NUMBER_OFFSET)[0]
    magic_number_be = struct.unpack_from(">L", data, MAGIC_NUMBER_OFFSET)[0]

    if magic_number_le in (MAGIC_NUMBER1, MAGIC_NUMBER2):
        order = "<"
    elif magic_number_be in (MAGIC_NUMBER1, MAGIC_NUMBER2):
        order = ">"
    else:
        raise PcapError(
            f"Unknown magic number (got {hex(magic_number_le)}(LE) / {hex(magic_number_be)}(BE), expected one of [{hex(MAGIC_NUMBER1)}, {hex(MAGIC_NUMBER2)}])"
        )

    (
        _magic_number,
        _major_version,
        _minor_version,
        _reserved1,
        _reserved2,
        _snaplen,
        link_type,
    ) = struct.unpack_from(order + "LHHLLLL", data, GLOBAL_HEADER_OFFSET)

    link_type = link_type & LINK_TYPE_MASK
    if link_type != EXPECTED_LINK_TYPE:
        raise PcapError(f"Invalid link type (got: {link_type}, expected: {EXPECTED_LINK_TYPE})")

    offset = GLOBAL_HEADER_LEN
    frames = []
    nr_frames = 0
    while offset < len(data):
        if len(data) < offset + PACKET_RECORD_HEADER_LEN:
            raise PcapError(
                f"Truncated pcap at frame {nr_frames + 1} (got {len(data) - offset} of {PACKET_RECORD_HEADER_LEN} bytes)"
            )

        _time1, _time2, cap_len, orig_len = struct.unpack_from(order + "LLLL", data, offset)

        if cap_len < orig_len:
            raise PcapError(f"Incomplete frame {nr_frames + 1} (got {cap_len} of {orig_len} bytes)")

        if len(data) < offset + PACKET_RECORD_HEADER_LEN + cap_len:
            raise PcapError(
                f"Truncated pcap at frame {nr_frames + 1} (got {len(data) - offset} of {PACKET_RECORD_HEADER_LEN + cap_len} bytes)"
            )

        frame_start = offset + PACKET_RECORD_HEADER_LEN
        frame_end = frame_start + cap_len
        frames.append(Frame(frameno=nr_frames + 1, data=data[frame_start:frame_end]))
        nr_frames += 1
        offset += PACKET_RECORD_HEADER_LEN + cap_len

    return PcapData(link_type=link_type, frames=frames)
