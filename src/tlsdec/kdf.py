import hashlib
import hmac

from tlsdec.errors import KdfError


def hkdf_expand(prk: bytes, info: bytes, length: int, hash_alg: str) -> bytes:
    hash_mod = hashlib.new(hash_alg)
    digest_size = hash_mod.digest_size

    if length > 255 * digest_size:
        raise KdfError(
            f"Cannot expand to requested length {length} (limit {255 * digest_size} bytes)."
        )

    output = b""
    previous = b""
    counter = 1
    while len(output) < length:
        message = previous + info + counter.to_bytes(1, "big")
        previous = hmac.digest(prk, message, hash_mod.name)
        output += previous
        counter += 1

    return output[:length]
