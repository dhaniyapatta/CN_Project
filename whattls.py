#!/usr/bin/env python3.6

import sys
import os
import pyshark
import csv
from mappings import TLS_VERSION_MAPPING, CIPHER_SUITE_MAPPING


def get_ssl_streams(cap):
    ssl_handshake_packets = []
    handshake_tuples_list = []
    for pkt in cap:
        if pkt.highest_layer == "SSL" and pkt.ssl.get_field("handshake") is not None:
            if "Client Hello" in pkt.ssl.get_field(
                "handshake"
            ) or "Server Hello" in pkt.ssl.get_field("handshake"):
                ssl_handshake_packets.append(pkt)
    match = False
    for i in ssl_handshake_packets:
        client_hello_pkt = None
        server_hello_pkt = None
        if "Client Hello" in i.ssl.get_field("handshake"):
            client_hello_pkt = i
            client_hello_stream = int(i.tcp.stream)
            for j in ssl_handshake_packets:
                if (
                    "Server Hello" in j.ssl.get_field("handshake")
                    and int(j.tcp.stream) == client_hello_stream
                ):
                    server_hello_pkt = j
                if client_hello_pkt is not None and server_hello_pkt is not None:
                    handshake_tuples_list.append((client_hello_pkt, server_hello_pkt))
                    match = True
                    if match:
                        break

    return handshake_tuples_list


def get_negotiated_tls_version(pkt):
    try:
        return TLS_VERSION_MAPPING[str(pkt.ssl.get_field("handshake_version"))]
    except KeyError:
        return str(pkt.ssl.get_field("handshake_version"))


def get_negotiated_cipher_suite(pkt):
    try:
        return CIPHER_SUITE_MAPPING[str(hex(int(pkt.ssl.get("handshake_ciphersuite"))))]
    except KeyError:
        return str(hex(int(pkt.ssl.get("handshake_ciphersuite"))))


def main(args):
    cap_file = args[1]
    filename, _ = os.path.splitext(args[1])
    cap_file = args[1]
    cap = pyshark.FileCapture(cap_file, display_filter="ssl")
    ssl_streams = get_ssl_streams(cap)
    # print(ssl_streams)
    ssl_connections = []
    for stream in ssl_streams:
        client_hello_pkt = stream[0]
        server_hello_pkt = stream[1]
        session_data = {
            "capture_file": cap_file,
            "tcp_stream_id": str(client_hello_pkt.tcp.stream),
            "client_hello": str(client_hello_pkt.ssl),
            "server_hello": str(server_hello_pkt.ssl),
            "negotiated_tls_version": get_negotiated_tls_version(server_hello_pkt),
            "negotiated_cipher_suite": get_negotiated_cipher_suite(server_hello_pkt),
        }
        ssl_connections.append(session_data)
        print(
            f"Found TLS connection! TCP stream {client_hello_pkt.tcp.stream} used {session_data['negotiated_tls_version']} and {session_data['negotiated_cipher_suite']}"
        )

    with open(filename + ".csv", "w") as f:
        keys = ssl_connections[0].keys()
        dict_writer = csv.DictWriter(f, keys)
        dict_writer.writeheader()
        dict_writer.writerows(ssl_connections)

    print(f"Saved data to {filename}.csv")
    # Fix for asyncio bug with pyshark
    cap.close()
    # Fix for asyncio bug that keeps looping over capture
    sys.exit()


if __name__ == "__main__":
    while True:
        try:
            main(sys.argv)
        except KeyboardInterrupt:
            print("User canceled. Exiting...")
            sys.exit(1)