import pytest

from tlsdec.decrypt import get_nonce, get_tls_inner_plaintext
from tlsdec.errors import DecryptError
from tlsdec.record import TlsContentType

IV = bytes.fromhex("00112233445566778899AABB")
INNER_PLAINTEXT = bytes("lorem ipsum dolor sit amet", "utf-8")


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


def test_get_tls_inner_plaintext_all_zero():
    data = 32 * b"\x00"
    with pytest.raises(DecryptError, match="no non-zero byte found"):
        get_tls_inner_plaintext(data)


def test_get_tls_inner_plaintext_unknown_content_type():
    data = 16 * b"\x00" + b"\x13" + 15 * b"\x00"
    with pytest.raises(DecryptError, match="Unknown content type"):
        get_tls_inner_plaintext(data)


def test_get_tls_inner_plaintext_no_padding():
    data = INNER_PLAINTEXT + bytes([TlsContentType.APPLICATION_DATA])
    res = get_tls_inner_plaintext(data)
    assert res.content_type == TlsContentType.APPLICATION_DATA
    assert res.content == INNER_PLAINTEXT


def test_get_tls_inner_plaintext_some_padding():
    data = INNER_PLAINTEXT + bytes([TlsContentType.APPLICATION_DATA]) + 16 * b"\x00"
    res = get_tls_inner_plaintext(data)
    assert res.content_type == TlsContentType.APPLICATION_DATA
    assert res.content == INNER_PLAINTEXT


def test_get_tls_inner_plaintext_allzero_content():
    content = 32 * b"\x00"
    data = content + bytes([TlsContentType.APPLICATION_DATA]) + 16 * b"\x00"
    res = get_tls_inner_plaintext(data)
    assert res.content_type == TlsContentType.APPLICATION_DATA
    assert res.content == content


def test_get_tls_inner_plaintext_empty_content():
    data = bytes([TlsContentType.APPLICATION_DATA]) + 16 * b"\x00"
    res = get_tls_inner_plaintext(data)
    assert res.content_type == TlsContentType.APPLICATION_DATA
    assert res.content == b""


def test_get_tls_inner_plaintext_invalid_content_type():
    data = bytes([TlsContentType.CHANGE_CIPHER_SPEC]) + 16 * b"\x00"
    with pytest.raises(DecryptError, match="Invalid content type"):
        get_tls_inner_plaintext(data)
