from tlsdec.kdf import hkdf_expand, hkdf_expand_label


def test_hkdf_expand():
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    length = 42
    prk = bytes.fromhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
    okm = bytes.fromhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    assert hkdf_expand(prk, info, length, "sha256") == okm


def test_hkdf_expand_label():
    prk = bytes.fromhex(
        "b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38"
    )
    key_expanded = bytes.fromhex("3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc")
    iv_expanded = bytes.fromhex("5d 31 3e b2 67 12 76 ee 13 00 0b 30")

    assert hkdf_expand_label(prk, b"key", b"", 16, "sha256") == key_expanded
    assert hkdf_expand_label(prk, b"iv", b"", 12, "sha256") == iv_expanded
