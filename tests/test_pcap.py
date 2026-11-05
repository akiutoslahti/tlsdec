# ruff: noqa: PLR2004
from pathlib import Path

import pytest

from tlsdec.errors import PcapError
from tlsdec.pcap import pcap_parse

PATH = Path(__file__).parent / "fixtures" / "fixture-TLS_AES_128_GCM_SHA256.pcap"


def test_pcap_parse():
    parsed = pcap_parse(PATH.read_bytes())
    assert parsed.link_type == 1
    assert len(parsed.frames) == 19


def test_pcap_parse_truncated():
    with pytest.raises(PcapError):
        pcap_parse(PATH.read_bytes()[:-1])
