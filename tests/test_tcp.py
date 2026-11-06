# ruff: noqa: PLR2004

import pytest
import testconf

from tlsdec.errors import TcpError
from tlsdec.pcap import pcap_parse
from tlsdec.tcp import Segment, tcp_parse_frame, tcp_reassemble_flow

LOCALHOST_IP = int.from_bytes(b"\x7f\x00\x00\x01", "big")


def test_tcp_parse_frame():
    parsed_pcap = pcap_parse(testconf.PATH_FIXTURE_AES_128.read_bytes())
    segments = [tcp_parse_frame(frame) for frame in parsed_pcap.frames]
    assert segments[0].syn
    assert segments[1].syn
    assert segments[16].fin
    assert segments[17].fin
    assert len(segments[3].payload) == 517
    assert len(segments[5].payload) == 741
    assert len(segments[7].payload) == 64
    assert len(segments[8].payload) == 99
    assert len(segments[12].payload) == 5040


def test_tcp_reassemble_flow():
    parsed_pcap = pcap_parse(testconf.PATH_FIXTURE_AES_128.read_bytes())
    segments = [tcp_parse_frame(frame) for frame in parsed_pcap.frames]
    flow = tcp_reassemble_flow(segments)
    assert flow.client.port == 46430
    assert flow.server.port == 4443
    assert len(flow.client_stream) == 704
    assert len(flow.server_stream) == 6283


def test_tcp_reassemble_flow_out_of_order():
    syn = Segment(
        frameno=4,
        source_address=LOCALHOST_IP,
        source_port=46430,
        destination_address=LOCALHOST_IP,
        destination_port=4443,
        sequence_number=1,
        syn=True,
        fin=False,
        ack=False,
        payload=b"",
    )
    syn_ack = Segment(
        frameno=5,
        source_address=LOCALHOST_IP,
        source_port=4443,
        destination_address=LOCALHOST_IP,
        destination_port=46430,
        sequence_number=1001,
        syn=True,
        fin=False,
        ack=True,
        payload=b"",
    )
    payload1 = Segment(
        frameno=2,
        source_address=LOCALHOST_IP,
        source_port=46430,
        destination_address=LOCALHOST_IP,
        destination_port=4443,
        sequence_number=2,
        syn=False,
        fin=False,
        ack=False,
        payload=b"\xaa\xaa",
    )
    payload2 = Segment(
        frameno=3,
        source_address=LOCALHOST_IP,
        source_port=4443,
        destination_address=LOCALHOST_IP,
        destination_port=46430,
        sequence_number=1002,
        syn=False,
        fin=False,
        ack=False,
        payload=b"\xaa\xaa\xaa",
    )
    payload3 = Segment(
        frameno=1,
        source_address=LOCALHOST_IP,
        source_port=46430,
        destination_address=LOCALHOST_IP,
        destination_port=4443,
        sequence_number=4,
        syn=False,
        fin=False,
        ack=False,
        payload=b"\xaa\xaa\xaa\xaa",
    )

    segments = [payload3, payload1, payload2, syn, syn_ack]
    flow = tcp_reassemble_flow(segments)

    assert flow.client.port == 46430
    assert flow.server.port == 4443
    assert len(flow.client_stream) == 6
    assert len(flow.server_stream) == 3


def test_tcp_reassemble_flow_gap():
    syn = Segment(
        frameno=1,
        source_address=LOCALHOST_IP,
        source_port=46430,
        destination_address=LOCALHOST_IP,
        destination_port=4443,
        sequence_number=1,
        syn=True,
        fin=False,
        ack=False,
        payload=b"",
    )
    syn_ack = Segment(
        frameno=2,
        source_address=LOCALHOST_IP,
        source_port=4443,
        destination_address=LOCALHOST_IP,
        destination_port=46430,
        sequence_number=1001,
        syn=True,
        fin=False,
        ack=True,
        payload=b"",
    )
    payload2 = Segment(
        frameno=4,
        source_address=LOCALHOST_IP,
        source_port=4443,
        destination_address=LOCALHOST_IP,
        destination_port=46430,
        sequence_number=1002,
        syn=False,
        fin=False,
        ack=False,
        payload=b"\xaa\xaa\xaa",
    )
    payload3 = Segment(
        frameno=5,
        source_address=LOCALHOST_IP,
        source_port=46430,
        destination_address=LOCALHOST_IP,
        destination_port=4443,
        sequence_number=4,
        syn=False,
        fin=False,
        ack=False,
        payload=b"\xaa\xaa\xaa\xaa",
    )

    segments = [syn, syn_ack, payload2, payload3]
    with pytest.raises(TcpError, match="Gap"):
        tcp_reassemble_flow(segments)
