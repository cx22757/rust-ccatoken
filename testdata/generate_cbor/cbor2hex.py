#!/usr/bin/env python3
import sys
import binascii
import textwrap


def dump_cbor_to_hex(path: str, wrap: int = 32):
    """
    将二进制 CBOR 文件原样转成 HEX 字符串
    可直接用于 constants.rs
    """

    with open(path, "rb") as f:
        data = f.read()

    hex_str = binascii.hexlify(data).decode("ascii")

    wrapped = "\n".join(
        textwrap.wrap(hex_str, wrap * 2)
    )

    print("\n========== RAW HEX ==========\n")
    print(hex_str)

    print("\n========== RUST CONSTANT ==========\n")
    print('pub const TEMPLATE_TOKEN_HEX: &str = "')
    print(wrapped)
    print('";')

    print("\n========== LENGTH ==========")
    print(f"bytes = {len(data)}")
    print(f"hex   = {len(hex_str)}")


def main():
    if len(sys.argv) != 2:
        print("Usage:")
        print("  python3 cbor_to_hex.py <cca_token.cbor>")
        sys.exit(1)

    dump_cbor_to_hex(sys.argv[1])


if __name__ == "__main__":
    main()
