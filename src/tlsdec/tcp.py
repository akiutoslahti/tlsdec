import ipaddress
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


class Endpoint(NamedTuple):
    address: int
    port: int


class Flow(NamedTuple):
    client: Endpoint
    server: Endpoint
    client_stream: bytes
    server_stream: bytes


def tcp_get_stream_position(seqno: int, isn: int) -> int:
    return (seqno - isn - 1) % 2**32


def tcp_get_endpoint_str(endpoint: Endpoint) -> str:
    return f"{ipaddress.IPv4Address(endpoint.address)}:{endpoint.port}"


def tcp_join_payloads(segments: list[Segment], isn: int) -> bytes:
    expected_position = 0
    stream = []
    for seg in segments:
        stream_pos = tcp_get_stream_position(seg.sequence_number, isn)
        if expected_position < stream_pos:
            raise TcpError(
                f"Gap in stream; source {tcp_get_endpoint_str(Endpoint(seg.source_address, seg.source_port))}, destination {tcp_get_endpoint_str(Endpoint(seg.destination_address, seg.destination_port))}, frameno {seg.frameno}, position {stream_pos}, expected position {expected_position}"
            )
        elif expected_position > stream_pos:
            raise TcpError(
                f"Overlap in stream; source {tcp_get_endpoint_str(Endpoint(seg.source_address, seg.source_port))}, destination {tcp_get_endpoint_str(Endpoint(seg.destination_address, seg.destination_port))}, frameno {seg.frameno}, position {stream_pos}, expected position {expected_position}"
            )
        else:
            stream.append(seg.payload)
            expected_position += len(seg.payload)
    return b"".join(stream)


def tcp_segment_belongs_to_flow(seg: Segment, client: Endpoint, server: Endpoint) -> bool:
    source = Endpoint(address=seg.source_address, port=seg.source_port)
    destination = Endpoint(address=seg.destination_address, port=seg.destination_port)
    return (source == client and destination == server) or (source == server and destination == client)


def tcp_reassemble_flow(segments: list[Segment]) -> Flow:
    syn_segments = [seg for seg in segments if seg.syn and not seg.ack]
    if len(syn_segments) != 1:
        raise TcpError(f"Can't establish flow; {len(syn_segments)} SYN segments")

    syn_ack_segments = [seg for seg in segments if seg.syn and seg.ack]
    if len(syn_ack_segments) != 1:
        raise TcpError(f"Can't establish flow; {len(syn_ack_segments)} SYN+ACK segments")

    syn_segment = syn_segments[0]
    syn_ack_segment = syn_ack_segments[0]
    if (
        syn_segment.source_address != syn_ack_segment.destination_address
        or syn_segment.source_port != syn_ack_segment.destination_port
        or syn_segment.destination_address != syn_ack_segment.source_address
        or syn_segment.destination_port != syn_ack_segment.source_port
    ):
        raise TcpError("Can't establish flow; SYN and SYN+ACK segments disagree in endpoints")

    if len(syn_segment.payload) != 0:
        raise TcpError(
            f"Can't establish flow; SYN in frame {syn_segment.frameno} carries {len(syn_segment.payload)} bytes (TCP Fast Open)"
        )

    if len(syn_ack_segment.payload) != 0:
        raise TcpError(
            f"Can't establish flow; SYN+ACK in frame {syn_ack_segment.frameno} carries {len(syn_ack_segment.payload)} bytes (TCP Fast Open)"
        )

    client = Endpoint(address=syn_segment.source_address, port=syn_segment.source_port)
    server = Endpoint(address=syn_segment.destination_address, port=syn_segment.destination_port)
    client_isn = syn_segment.sequence_number
    server_isn = syn_ack_segment.sequence_number

    for seg in segments:
        if not tcp_segment_belongs_to_flow(seg, client, server):
            raise TcpError(
                f"Segment doesn't belong to flow; frameno {seg.frameno}, source {tcp_get_endpoint_str(Endpoint(seg.source_address, seg.source_port))}, destination {tcp_get_endpoint_str(Endpoint(seg.destination_address, seg.destination_port))}"
            )

    client_segments = [
        seg
        for seg in segments
        if seg.source_address == client.address and seg.source_port == client.port and len(seg.payload) > 0
    ]
    server_segments = [
        seg
        for seg in segments
        if seg.source_address == server.address and seg.source_port == server.port and len(seg.payload) > 0
    ]

    client_segments.sort(key=lambda seg: tcp_get_stream_position(seg.sequence_number, client_isn))
    server_segments.sort(key=lambda seg: tcp_get_stream_position(seg.sequence_number, server_isn))

    client_stream = tcp_join_payloads(client_segments, client_isn)
    server_stream = tcp_join_payloads(server_segments, server_isn)

    return Flow(client=client, server=server, client_stream=client_stream, server_stream=server_stream)
