import struct
from typing import NamedTuple

from tlsdec.errors import TcpError
from tlsdec.pcap import Frame

HI_NIBBLE_SHIFT = 4
LO_NIBBLE_MASK = 0xF

ETHERNET_HEADER_LEN = 14
ETHERTYPE_OFFSET = 12
ETHERTYPE_IPV4 = int.from_bytes(b"\x08\x00", "big")

IPV4_HEADER_LEN = 20
IPV4_VERSION = 4
IHL_MUL = 4
FLAGS_SHIFT = 13
FRAGMENT_OFFSET_MASK = 0x1FFF
MF_FLAG = 0x1
TCP_PROTOCOL = 6

TCP_HEADER_LEN_MIN = 20
DATA_OFFSET_MUL = 4
FIN_FLAG = 0x01
SYN_FLAG = 0x02
ACK_FLAG = 0x10


class Segment(NamedTuple):
    frameno: int
    source_address: int
    source_port: int
    destination_address: int
    destination_port: int
    sequence_number: int
    syn: bool
    fin: bool
    ack: bool
    payload: bytes


def tcp_parse_frame(frame: Frame) -> Segment:
    frameno = frame.frameno
    l1_packet = frame.data
    if len(l1_packet) < ETHERNET_HEADER_LEN:
        raise TcpError(
            f"[frame {frameno}] Can't extract ethernet header; truncated (got {len(l1_packet)} of {ETHERNET_HEADER_LEN} bytes)"
        )

    ethertype = struct.unpack_from("!H", l1_packet, ETHERTYPE_OFFSET)[0]
    if ethertype != ETHERTYPE_IPV4:
        raise TcpError(f"[frame {frameno}] Wrong ethertype (got {hex(ethertype)}, expected {hex(ETHERTYPE_IPV4)})")

    l2_packet = l1_packet[ETHERNET_HEADER_LEN:]
    if len(l2_packet) < IPV4_HEADER_LEN:
        raise TcpError(
            f"[frame {frameno}] Can't extract IPv4 header; truncated (got {len(l2_packet)} of {IPV4_HEADER_LEN} bytes)"
        )

    (
        version_and_ihl,
        _type_of_service,
        total_length,
        _identification,
        flags_and_fragment_offset,
        _time_to_live,
        protocol,
        _header_checksum,
        source_address,
        destination_address,
    ) = struct.unpack_from("!BBHHHBBHLL", l2_packet, 0)

    version = version_and_ihl >> HI_NIBBLE_SHIFT
    if version != IPV4_VERSION:
        raise TcpError(f"[frame {frameno}] Wrong IP version (got {version}, expected {IPV4_VERSION})")

    ihl = (version_and_ihl & LO_NIBBLE_MASK) * IHL_MUL
    if ihl < IPV4_HEADER_LEN or ihl > len(l2_packet):
        raise TcpError(
            f"[frame {frameno}] Invalid IHL (got {ihl}, expected {IPV4_HEADER_LEN} <= X <= {len(l2_packet)})"
        )

    if ihl > total_length or total_length > len(l2_packet):
        raise TcpError(
            f"[frame {frameno}] Invalid total length (expected {ihl}(ihl) <= {total_length}(total length) <= {len(l2_packet)}(available))"
        )

    l2_flags = flags_and_fragment_offset >> FLAGS_SHIFT
    if l2_flags & MF_FLAG != 0:
        raise TcpError(f"[frame {frameno}] MF flag set")

    fragment_offset = flags_and_fragment_offset & FRAGMENT_OFFSET_MASK
    if fragment_offset != 0:
        raise TcpError(f"[frame {frameno}] non-zero fragment offset")

    if protocol != TCP_PROTOCOL:
        raise TcpError(f"[frame {frameno}] Wrong protocol (got {protocol}, expected {TCP_PROTOCOL})")

    l3_packet = l2_packet[ihl:total_length]
    if len(l3_packet) < TCP_HEADER_LEN_MIN:
        raise TcpError(
            f"[frame {frameno}] Can't extract TCP header; truncated (got {len(l3_packet)} of minimum of {TCP_HEADER_LEN_MIN} bytes)"
        )

    (
        source_port,
        destination_port,
        sequence_number,
        _acknowledgement_number,
        data_offset,
        tcp_flags,
        _window,
        _checksum,
        _urgent_pointer,
    ) = struct.unpack_from("!HHLLBBHHH", l3_packet, 0)

    data_offset = (data_offset >> HI_NIBBLE_SHIFT) * DATA_OFFSET_MUL

    if data_offset < TCP_HEADER_LEN_MIN or data_offset > len(l3_packet):
        raise TcpError(
            f"[frame {frameno}] Invalid TCP header length (got {data_offset}, expected {TCP_HEADER_LEN_MIN} <= X <= {len(l3_packet)})"
        )

    syn = tcp_flags & SYN_FLAG != 0
    fin = tcp_flags & FIN_FLAG != 0
    ack = tcp_flags & ACK_FLAG != 0

    payload = l3_packet[data_offset:]

    return Segment(
        frameno=frameno,
        source_address=source_address,
        source_port=source_port,
        destination_address=destination_address,
        destination_port=destination_port,
        sequence_number=sequence_number,
        syn=syn,
        fin=fin,
        ack=ack,
        payload=payload,
    )
