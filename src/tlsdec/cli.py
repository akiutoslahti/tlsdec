import argparse
import sys
from pathlib import Path

from tlsdec.errors import TlsdecError
from tlsdec.pcap import pcap_parse
from tlsdec.record import TlsRecord, record_split
from tlsdec.tcp import Endpoint, tcp_get_endpoint_str, tcp_parse_frame, tcp_reassemble_flow


def print_direction(source: Endpoint, destination: Endpoint) -> None:
    print(f"{tcp_get_endpoint_str(source)} -> {tcp_get_endpoint_str(destination)}")


def print_records(records: list[TlsRecord]) -> None:
    for record in records:
        print(f"index: {record.idx}, content type: {record.content_type.name}, length: {record.length}")


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
    except TlsdecError as err:
        print(err, file=sys.stderr)
        return 1

    client = flow.client
    server = flow.server

    print_direction(client, server)
    print_records(client_records)
    print()
    print_direction(server, client)
    print_records(server_records)

    return 0
