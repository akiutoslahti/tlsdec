# ruff: noqa: PLR2004

import testconf

from tlsdec.pcap import pcap_parse
from tlsdec.tcp import tcp_parse_frame


def test_tcp_parse_frame():
    parsed_pcap = pcap_parse(testconf.PATH_FIXTURE_AES_128.read_bytes())
    segments = []
    for frame in parsed_pcap.frames:
        segments.append(tcp_parse_frame(frame))
    assert segments[0].syn
    assert segments[1].syn
    assert segments[16].fin
    assert segments[17].fin
    assert len(segments[3].payload) == 517
    assert len(segments[5].payload) == 741
    assert len(segments[7].payload) == 64
    assert len(segments[8].payload) == 99
    assert len(segments[12].payload) == 5040
