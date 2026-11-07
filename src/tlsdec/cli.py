import argparse
import string
import sys
from pathlib import Path

from tlsdec.decrypt import TlsDecryptResult, tls_decrypt_direction
from tlsdec.errors import TlsdecError
from tlsdec.handshake import parse_client_hello, parse_handshake, parse_server_hello
from tlsdec.kdf import get_traffic_keys
from tlsdec.keylog import keylog_parse
from tlsdec.pcap import pcap_parse
from tlsdec.record import TlsContentType, record_split
from tlsdec.tcp import Endpoint, tcp_get_endpoint_str, tcp_parse_frame, tcp_reassemble_flow


def print_direction(source: Endpoint, destination: Endpoint) -> None:
    print(f"{tcp_get_endpoint_str(source)} -> {tcp_get_endpoint_str(destination)}")


def print_decrypted_records(records: list[TlsDecryptResult]) -> None:
    for record in records:
        record_printout = []
        appdata_printout = ""

        record_printout.append(f"index: {record.record_index}")
        record_printout.append(f"outer type: {record.outer_type.name}")
        record_printout.append(f"outer length: {record.outer_length}")
        record_printout.append(f"decryption key: {record.decrypt_key.name if record.decrypt_key is not None else '-'}")
        record_printout.append(
            f"sequence number: {record.record_sequence_number if record.record_sequence_number is not None else '-'}"
        )

        if record.inner_type is not None:
            record_printout.append(f"inner type: {record.inner_type.name}")

        if record.inner_type == TlsContentType.HANDSHAKE and len(record.handshake_types) != 0:
            handshake_types = [x.name for x in record.handshake_types]
            record_printout.append(f"handshake type(s): {', '.join(handshake_types)}")

        if record.inner_type == TlsContentType.ALERT and record.inner_content is not None:
            record_printout.append(f"level: {record.inner_content[0]}, description: {record.inner_content[1]}")

        if record.inner_type == TlsContentType.APPLICATION_DATA and record.inner_content is not None:
            printable = bytes(string.printable, "ascii")
            if all(b in printable for b in record.inner_content):
                appdata_printout = record.inner_content.decode("ascii")
            else:
                appdata_printout = record.inner_content.hex()

        print(f"[{', '.join(record_printout)}]")
        if len(appdata_printout) != 0:
            print(appdata_printout)


def main(args: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tlsdec", description="TLS 1.3 session decryptor: pcap plus key log in, plaintext out"
    )
    parser.add_argument("--pcap", help="PATH to packet capture file", required=True)
    parser.add_argument("--keylog", help="PATH to SSLKEYLOG file", required=True)

    parsed_args = parser.parse_args(args)

    try:
        data = Path(parsed_args.pcap).read_bytes()
        parsed_pcap = pcap_parse(data)
        segments = [tcp_parse_frame(frame) for frame in parsed_pcap.frames]
        flow = tcp_reassemble_flow(segments)
        client_records = record_split(flow.client_stream)
        server_records = record_split(flow.server_stream)
        client_hello = parse_handshake(client_records[0].body)
        server_hello = parse_handshake(server_records[0].body)
        client_random = parse_client_hello(client_hello)
        cipher_suite = parse_server_hello(server_hello)

        keylog = Path(parsed_args.keylog).read_text()
        secrets = keylog_parse(keylog, client_random)

        client_hs_keys = get_traffic_keys(cipher_suite, secrets.client_handshake)
        client_app_keys = get_traffic_keys(cipher_suite, secrets.client_application)
        server_hs_keys = get_traffic_keys(cipher_suite, secrets.server_handshake)
        server_app_keys = get_traffic_keys(cipher_suite, secrets.server_application)

        client_records_plain = tls_decrypt_direction(client_records, client_hs_keys, client_app_keys)
        server_records_plain = tls_decrypt_direction(server_records, server_hs_keys, server_app_keys)
    except TlsdecError as err:
        print(err, file=sys.stderr)
        return 1

    client = flow.client
    server = flow.server

    print_direction(client, server)
    print_decrypted_records(client_records_plain)
    print()
    print_direction(server, client)
    print_decrypted_records(server_records_plain)

    return 0
