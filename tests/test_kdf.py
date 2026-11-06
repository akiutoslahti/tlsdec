import pytest

from tlsdec.errors import KdfError
from tlsdec.kdf import CipherSuite, get_traffic_keys, hkdf_expand, hkdf_expand_label


def test_hkdf_expand_rfc5869_tc1():
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    length = 42
    prk = bytes.fromhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
    okm = bytes.fromhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    assert hkdf_expand(prk, info, length, "sha256") == okm


def test_hkdf_expand_label_rfc8448_server_hs():
    prk = bytes.fromhex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
    key = bytes.fromhex("3fce516009c21727d0f2e4e86ee403bc")
    iv = bytes.fromhex("5d313eb2671276ee13000b30")

    assert hkdf_expand_label(prk, b"key", b"", 16, "sha256") == key
    assert hkdf_expand_label(prk, b"iv", b"", 12, "sha256") == iv


def test_get_traffic_keys1_rfc8448_server_hs():
    prk = bytes.fromhex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
    key = bytes.fromhex("3fce516009c21727d0f2e4e86ee403bc")
    iv = bytes.fromhex("5d313eb2671276ee13000b30")

    traffic_keys = get_traffic_keys(CipherSuite.TLS_AES_128_GCM_SHA256, prk)

    assert traffic_keys.key == key
    assert traffic_keys.iv == iv


def test_get_traffic_keys_rfc8448_server_app():
    prk = bytes.fromhex("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643")
    key = bytes.fromhex("9f02283b6c9c07efc26bb9f2ac92e356")
    iv = bytes.fromhex("cf782b88dd83549aadf1e984")

    traffic_keys = get_traffic_keys(CipherSuite.TLS_AES_128_GCM_SHA256, prk)

    assert traffic_keys.key == key
    assert traffic_keys.iv == iv


def test_get_traffic_keys_aes256_fixture_client_hs():
    prk = bytes.fromhex(
        "be99fd048e9aa172d0d30fc565f4fb5ccb5bade8c8d650e9517fa590b178d376d9d7481f4d8f16a03c59bb9b907a405e"
    )
    key = bytes.fromhex("822c5f57e71c2804ca37598d25b8a26fe8b70fb3aea390958d9f7e9fe87551ef")
    iv = bytes.fromhex("e2762b8d47177eec2c6a293d")

    traffic_keys = get_traffic_keys(CipherSuite.TLS_AES_256_GCM_SHA384, prk)

    assert traffic_keys.key == key
    assert traffic_keys.iv == iv


def test_get_traffic_keys_wrong_secret_length_aes128():
    prk = bytes.fromhex(
        "be99fd048e9aa172d0d30fc565f4fb5ccb5bade8c8d650e9517fa590b178d376d9d7481f4d8f16a03c59bb9b907a405e"
    )
    with pytest.raises(KdfError, match="Secret has incorrect length"):
        get_traffic_keys(CipherSuite.TLS_AES_128_GCM_SHA256, prk)


def test_get_traffic_keys_wrong_secret_length_aes256():
    prk = bytes.fromhex("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643")
    with pytest.raises(KdfError, match="Secret has incorrect length"):
        get_traffic_keys(CipherSuite.TLS_AES_256_GCM_SHA384, prk)
