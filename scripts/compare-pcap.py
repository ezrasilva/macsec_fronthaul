#!/usr/bin/env python3
"""Compare packet payloads in two little-endian PCAP files."""

import argparse
import struct


def read_packets(path: str) -> list[bytes]:
    result = []
    with open(path, "rb") as capture:
        if len(capture.read(24)) != 24:
            raise ValueError(f"invalid PCAP: {path}")
        while record := capture.read(16):
            if len(record) != 16:
                raise ValueError(f"truncated record: {path}")
            length = struct.unpack("<IIII", record)[2]
            packet = capture.read(length)
            if len(packet) != length:
                raise ValueError(f"truncated packet: {path}")
            result.append(packet)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("expected")
    parser.add_argument("actual")
    args = parser.parse_args()
    expected = read_packets(args.expected)
    actual = read_packets(args.actual)
    if expected != actual:
        raise ValueError(f"PCAPs differ: expected={len(expected)} actual={len(actual)}")
    print(f"Round-trip eCPRI idêntico: frames={len(actual)}")


if __name__ == "__main__":
    main()
