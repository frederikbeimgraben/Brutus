#!/usr/bin/env python3
"""
Encrypts a file using the local "encrypt.py" library.
"""

# Standard imports
import sys
import os
from typing import Iterable
import argparse

# Local imports
from encrypt import caesar_encrypt_sequence, caesar_decrypt_sequence
from encrypt import vigenere_encrypt_sequence, vigenere_decrypt_sequence


BYTE_ALPHABET = [
    n for n in range(256)
]

def apply_byte_stream(
        func: callable,
        key: Iterable[int],
        byte_stream: Iterable[bytes]) -> Iterable[bytes]:
    """
    Encrypts a byte stream using the given function and key.
    """

    return func(
        (
            byte
            for byte in byte_stream
        ),
        key,
        BYTE_ALPHABET
    )

def apply_file(
        func: callable,
        key: Iterable[int],
        input_path: str,
        output_path: str) -> None:
    """
    Encrypts a file using the given function and key.
    """

    with open(input_path, 'rb') as input_file:
        with open(output_path, 'wb') as output_file:
            output_file.write(
                bytes(
                    apply_byte_stream(
                        func,
                        key,
                        input_file.read()
                    )
                )
            )

args = argparse.ArgumentParser(
    description='Encrypts a file using the local "encrypt.py" library.'
)
# -i, --input
args.add_argument(
    '-i',
    '--input',
    type=str,
    required=True,
    help='The path to the input file.'
)
# -o, --output
args.add_argument(
    '-o',
    '--output',
    type=str,
    required=True,
    help='The path to the output file.'
)
# -k, --key
args.add_argument(
    '-k',
    '--key',
    type=str,
    required=True,
    help='The key to use for encryption.'
)
# -f, --function
# Default: caesar
# Options: caesar, vigenere
args.add_argument(
    '-f',
    '--function',
    type=str,
    default='caesar',
    choices=['caesar', 'vigenere'],
    help='The encryption function to use.'
)
# -d, --decrypt
args.add_argument(
    '-d',
    '--decrypt',
    action='store_true',
    help='Decrypts the input file instead of encrypting it.'
)

if __name__ == '__main__':
    # Parse the arguments
    args = args.parse_args()

    # Get the key
    key = [ord(char) for char in args.key]

    # Get the function
    func = None
    if args.function == 'caesar':
        func = caesar_decrypt_sequence if args.decrypt else caesar_encrypt_sequence
    elif args.function == 'vigenere':
        func = vigenere_decrypt_sequence if args.decrypt else vigenere_encrypt_sequence

    # Encrypt the file
    apply_file(
        func,
        key,
        args.input,
        args.output
    )