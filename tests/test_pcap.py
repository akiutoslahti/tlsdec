# ruff: noqa: PLR2004

import pytest
import testconf

from tlsdec.errors import PcapError
from tlsdec.pcap import pcap_parse


def test_pcap_parse():
    parsed = pcap_parse(testconf.PATH_FIXTURE_AES_128.read_bytes())
    assert parsed.link_type == 1
    assert len(parsed.frames) == 19


def test_pcap_parse_truncated():
    with pytest.raises(PcapError):
        pcap_parse(testconf.PATH_FIXTURE_AES_128.read_bytes()[:-1])
