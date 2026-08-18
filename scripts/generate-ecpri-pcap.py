#!/usr/bin/env python3
"""Generate a small deterministic Ethernet/eCPRI capture without dependencies."""

import argparse
import struct
import time


def pcap_header() -> bytes:
    return struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def ecpri_frame(sequence: int) -> bytes:
    sequence &= 0xFFFF
    ethernet = bytes.fromhex("020000000002020000000001aefe")
    iq = bytes(((sequence + index) & 0xFF) for index in range(32))
    payload = struct.pack("!HH", 1, sequence) + iq
    # Revision 1, no concatenation; message type 0 (IQ Data).
    ecpri = struct.pack("!BBH", 0x10, 0x00, len(payload)) + payload
    frame = ethernet + ecpri
    return frame + bytes(max(0, 60 - len(frame)))


def write_capture(path: str, count: int) -> None:
    now = int(time.time())
    with open(path, "wb") as output:
        output.write(pcap_header())
        for sequence in range(count):
            frame = ecpri_frame(sequence)
            output.write(struct.pack("<IIII", now, sequence * 1000,
                                     len(frame), len(frame)))
            output.write(frame)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output")
    parser.add_argument("--count", type=int, default=32)
    args = parser.parse_args()
    if not 0 <= args.count <= 1000000:
        parser.error("--count must be between 0 and 1000000")
    write_capture(args.output, args.count)


if __name__ == "__main__":
    main()
