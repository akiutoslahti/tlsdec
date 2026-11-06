import struct

import pytest
import testconf

from tlsdec.errors import RecordError
from tlsdec.pcap import pcap_parse
from tlsdec.record import TLS_HEADER_LEN, TlsContentType, record_split
from tlsdec.tcp import tcp_parse_frame, tcp_reassemble_flow

TLS13_VER = 0x0303

RECORD1_BODY = b"\xaa\xaa"
RECORD1 = struct.pack("!BHH", TlsContentType.CHANGE_CIPHER_SPEC, TLS13_VER, len(RECORD1_BODY)) + RECORD1_BODY
RECORD2_BODY = b"\xaa\xaa\xaa"
RECORD2 = struct.pack("!BHH", TlsContentType.ALERT, TLS13_VER, len(RECORD2_BODY)) + RECORD2_BODY
RECORD3_BODY = b"\xaa\xaa\xaa\xaa"
RECORD3 = struct.pack("!BHH", TlsContentType.HANDSHAKE, TLS13_VER, len(RECORD3_BODY)) + RECORD3_BODY


def test_record_split():
    parsed_pcap = pcap_parse(testconf.PATH_FIXTURE_AES_128.read_bytes())
    segments = [tcp_parse_frame(frame) for frame in parsed_pcap.frames]
    flow = tcp_reassemble_flow(segments)
    client_records = record_split(flow.client_stream)
    server_records = record_split(flow.server_stream)

    client_type_length_pairs = [(record.content_type.value, record.length) for record in client_records]
    server_type_length_pairs = [(record.content_type.value, record.length) for record in server_records]

    client_type_length_pairs_expected = [(22, 512), (20, 1), (23, 53), (23, 94), (23, 19)]
    server_type_length_pairs_expected = [
        (22, 122),
        (20, 1),
        (23, 23),
        (23, 415),
        (23, 97),
        (23, 53),
        (23, 234),
        (23, 234),
        (23, 5035),
        (23, 19),
    ]

    assert client_type_length_pairs == client_type_length_pairs_expected
    assert server_type_length_pairs == server_type_length_pairs_expected


def test_record_split_back_to_back():
    records = record_split(RECORD1 + RECORD2 + RECORD3)

    assert records[0].content_type == TlsContentType.CHANGE_CIPHER_SPEC
    assert records[0].length == len(RECORD1_BODY)
    assert records[0].body == RECORD1_BODY
    assert records[0].header == RECORD1[:TLS_HEADER_LEN]

    assert records[1].content_type == TlsContentType.ALERT
    assert records[1].length == len(RECORD2_BODY)
    assert records[1].body == RECORD2_BODY
    assert records[1].header == RECORD2[:TLS_HEADER_LEN]

    assert records[2].content_type == TlsContentType.HANDSHAKE
    assert records[2].length == len(RECORD3_BODY)
    assert records[2].body == RECORD3_BODY
    assert records[2].header == RECORD3[:TLS_HEADER_LEN]


def test_record_split_cut_off_body():
    with pytest.raises(RecordError):
        record_split((RECORD1 + RECORD2 + RECORD3)[:-1])


def test_record_split_cut_off_header():
    with pytest.raises(RecordError):
        record_split((RECORD1 + RECORD2 + RECORD3)[: -(len(RECORD3_BODY) + 2)])
