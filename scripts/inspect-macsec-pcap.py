#!/usr/bin/env python3
"""Validate the restricted MACsec profile emitted by the PoC."""

import argparse
import struct


def packets(path: str):
    with open(path, "rb") as capture:
        header = capture.read(24)
        magic = struct.unpack("<I", header[:4])[0] if len(header) >= 4 else 0
        if len(header) != 24 or magic not in (0xA1B2C3D4, 0xA1B23C4D):
            raise ValueError("unsupported PCAP header")
        while record := capture.read(16):
            if len(record) != 16:
                raise ValueError("truncated PCAP record")
            _, _, captured, _ = struct.unpack("<IIII", record)
            frame = capture.read(captured)
            if len(frame) != captured:
                raise ValueError("truncated PCAP frame")
            yield frame


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("capture")
    parser.add_argument("--sci", required=True)
    parser.add_argument("--expected", type=int, required=True)
    args = parser.parse_args()
    expected_sci = bytes.fromhex(args.sci)
    previous_pn = 0
    count = 0
    for frame in packets(args.capture):
        if len(frame) < 46 or frame[12:14] != bytes.fromhex("88e5"):
            continue
        if frame[20:28] != expected_sci:
            raise ValueError("unexpected SCI")
        pn = struct.unpack("!I", frame[16:20])[0]
        if pn <= previous_pn:
            raise ValueError("packet numbers are not strictly increasing")
        if len(frame[-16:]) != 16:
            raise ValueError("missing ICV")
        previous_pn = pn
        count += 1
    if count != args.expected:
        raise ValueError(f"expected {args.expected} MACsec frames, found {count}")
    print(f"MACsec PCAP válido: frames={count} SCI={args.sci} PN-final={previous_pn} ICV=16")


if __name__ == "__main__":
    main()
