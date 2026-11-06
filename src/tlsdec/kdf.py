import hashlib
import hmac
from enum import IntEnum
from typing import NamedTuple

from tlsdec.errors import KdfError


class CipherSuite(IntEnum):
    TLS_AES_128_GCM_SHA256 = 0x1301
    TLS_AES_256_GCM_SHA384 = 0x1302


class CipherParameters(NamedTuple):
    hash_alg: str
    key_len: int
    iv_len: int


CIPHER_PARAMETERS_MAP = {
    CipherSuite.TLS_AES_128_GCM_SHA256: CipherParameters(hash_alg="sha256", key_len=16, iv_len=12),
    CipherSuite.TLS_AES_256_GCM_SHA384: CipherParameters(hash_alg="sha384", key_len=32, iv_len=12),
}


class TrafficKeys(NamedTuple):
    key: bytes
    iv: bytes


def hkdf_expand(prk: bytes, info: bytes, length: int, hash_alg: str) -> bytes:
    hash_mod = hashlib.new(hash_alg)
    digest_size = hash_mod.digest_size

    if length > 255 * digest_size:
        raise KdfError(f"Cannot expand to requested length {length} (limit {255 * digest_size} bytes).")

    output = b""
    previous = b""
    counter = 1
    while len(output) < length:
        message = previous + info + counter.to_bytes(1, "big")
        previous = hmac.digest(prk, message, hash_mod.name)
        output += previous
        counter += 1

    return output[:length]


def hkdf_expand_label(prk: bytes, label: bytes, context: bytes, length: int, hash_alg: str) -> bytes:
    full_label = b"tls13 " + label
    info = (
        length.to_bytes(2, "big")
        + len(full_label).to_bytes(1, "big")
        + full_label
        + len(context).to_bytes(1, "big")
        + context
    )
    return hkdf_expand(prk, info, length, hash_alg)


def get_traffic_keys(cipher_suite: CipherSuite, secret: bytes) -> TrafficKeys:
    cipher_params = CIPHER_PARAMETERS_MAP[cipher_suite]

    digest_size = hashlib.new(cipher_params.hash_alg).digest_size
    if len(secret) != digest_size:
        raise KdfError(f"Secret has incorrect length (got {len(secret)}, expected {digest_size} bytes)")

    key = hkdf_expand_label(
        prk=secret, label=b"key", context=b"", length=cipher_params.key_len, hash_alg=cipher_params.hash_alg
    )
    iv = hkdf_expand_label(
        prk=secret, label=b"iv", context=b"", length=cipher_params.iv_len, hash_alg=cipher_params.hash_alg
    )

    return TrafficKeys(key=key, iv=iv)
