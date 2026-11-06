from tlsdec.errors import DecryptError

IV_LEN = 12
SEQNO_LEN = 8


def get_nonce(iv: bytes, seqno: int) -> bytes:
    if len(iv) != IV_LEN:
        raise DecryptError(f"Invalid length IV (got {len(iv)}, expected {IV_LEN} bytes)")

    if seqno < 0:
        raise DecryptError(f"Invalid sequence number {seqno}; must be non-negative")

    try:
        seqno_padded = (IV_LEN - SEQNO_LEN) * b"\x00" + seqno.to_bytes(SEQNO_LEN, "big")
    except OverflowError as err:
        raise DecryptError(f"Invalid sequence number {seqno}; must fit into {SEQNO_LEN} bytes") from err

    return bytes(a ^ b for a, b in zip(seqno_padded, iv, strict=True))
