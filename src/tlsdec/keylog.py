from typing import NamedTuple

from tlsdec.errors import KeylogError

CLIENT_HANDSHAKE_LABEL = "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
CLIENT_LABEL = "CLIENT_TRAFFIC_SECRET_0"
SERVER_HANDSHAKE_LABEL = "SERVER_HANDSHAKE_TRAFFIC_SECRET"
SERVER_LABEL = "SERVER_TRAFFIC_SECRET_0"

CLIENT_RANDOM_LEN = 32
NR_ENTRIES_PER_ROW = 3


class Secrets(NamedTuple):
    client_handshake: bytes
    client_application: bytes
    server_handshake: bytes
    server_application: bytes


def keylog_parse(data: str, client_random: bytes) -> Secrets:
    secrets: dict[str, bytes] = {}
    for idx, line in enumerate(data.splitlines()):
        if len(line) == 0:
            continue
        if line.startswith("#"):
            continue

        split_line = line.split()

        if len(split_line) != NR_ENTRIES_PER_ROW:
            raise KeylogError(
                f"Malformed SSLKEYLOGFILE; got {len(split_line)} entries on line {idx + 1}, expected {NR_ENTRIES_PER_ROW}"
            )

        label = split_line[0]
        try:
            random = bytes.fromhex(split_line[1])
        except ValueError as err:
            raise KeylogError(f"Malformed SSLKEYLOGFILE; bad client random on line {idx + 1}") from err

        try:
            secret = bytes.fromhex(split_line[2])
        except ValueError as err:
            raise KeylogError(f"Malformed SSLKEYLOGFILE; bad secret on line {idx + 1}") from err

        if len(random) != CLIENT_RANDOM_LEN:
            raise KeylogError(
                f"Malformed SSLKEYLOGFILE; client random on line {idx + 1} has length of {len(random)}, expected {CLIENT_RANDOM_LEN}"
            )

        if random != client_random:
            continue

        if label in secrets:
            raise KeylogError(f"Duplicate label {label} for client random {client_random.hex()} on line {idx + 1}")

        secrets[label] = secret

    for label in [CLIENT_HANDSHAKE_LABEL, CLIENT_LABEL, SERVER_HANDSHAKE_LABEL, SERVER_LABEL]:
        if label not in secrets:
            raise KeylogError(f"Missing {label} for client random {client_random.hex()}")

    return Secrets(
        client_handshake=secrets[CLIENT_HANDSHAKE_LABEL],
        client_application=secrets[CLIENT_LABEL],
        server_handshake=secrets[SERVER_HANDSHAKE_LABEL],
        server_application=secrets[SERVER_LABEL],
    )
