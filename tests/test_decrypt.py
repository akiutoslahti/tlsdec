import pytest

from tlsdec.decrypt import get_nonce
from tlsdec.errors import DecryptError

IV = bytes.fromhex("00112233445566778899AABB")


def test_nonce():
    assert get_nonce(IV, 0) == IV
    assert get_nonce(IV, 1) == bytes.fromhex("00112233445566778899AABA")
    assert get_nonce(IV, 2**32) == bytes.fromhex("00112233445566768899AABB")
    assert get_nonce(IV, 2**64 - 1) == bytes.fromhex("00112233BBAA998877665544")


def test_nonce_negative_seqno():
    with pytest.raises(DecryptError, match="non-negative"):
        get_nonce(IV, -1)


def test_nonce_too_large_seqno():
    with pytest.raises(DecryptError, match="must fit"):
        get_nonce(IV, 2**64)


def test_nonce_invalid_iv():
    with pytest.raises(DecryptError, match="length IV"):
        get_nonce(IV + b"\x00", 0)
