"""
Encryption Algorithms for the project

Author:  Frederik Beimgraben (github/frederikbeimgraben)
Created: 2023/05/16

Contains:
    - Simple Caesar Shift
    - Vigenere Cipher
"""

# Imports
from functools import cache
from typing import Dict, Generator, Iterable, List, TypeVar, SupportsIndex


# Type Hints  (I just like type hints, okay?)
S = TypeVar("S")
A = List[S] | str
T = Iterable[S]


# Constants
ALPHABET: A = \
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890 !?.\n\t)]}{[(+-*/=<>@#$%^&|~`\\\"';:,_"


# Functions
## Invert the Alphabet Table
@cache
def invert_table(table: A=ALPHABET) -> A:
    """
    Inverts an alphabet table.

    Args:
        table (A, optional): The alphabet to invert. Defaults to ALPHABET.

    Returns:
        A: The inverted alphabet.
    """
    return {
        value: key
        for key, value in enumerate(table)
    }

## Hashing Algorithm to convert a sequence of symbols to an offset value 
## (For Caesar Shift by Word Key)
def hash_sequence(text: T, table: A=ALPHABET) -> int:
    """
    Hashes a sequence of symbols to an offset value.

    Args:
        text (T): The text to hash.
        table (A, optional): The alphabet to use. Defaults to ALPHABET.

    Returns:
        int: The hashed offset value.
    """

    INVERTED_TABLE: Dict[S, int] = invert_table(table)

    return sum(
        INVERTED_TABLE[symbol]
        for symbol in text
    ) % len(table)

def support_hashing(func: callable) -> callable:
    """
    Decorator to allow for hashing of sequences of symbols.

    Args:
        func (callable): The function to decorate.

    Returns:
        callable: The decorated function.
    """
    def wrapper(text: S | T, key: int | T, table: A=ALPHABET) -> int:
        if not isinstance(key, int):
            try:
                key = hash_sequence(key, table)
            except TypeError:
                raise TypeError("The key must be an integer or a sequence of symbols.")

        return func(text, key, table)

    return wrapper

## Shifting Algorithms
### Simple Caesar Shift
@support_hashing
def shift_symbol(symbol: S, shift: int, table: A=ALPHABET) -> S:
    """
    Shifts a symbol by a given shift value.

    Args:
        symbol (S): The symbol to shift.
        shift (int): The shift value.
        table (A, optional): The alphabet to use. Defaults to ALPHABET.

    Returns:
        S: The shifted symbol.
    """

    if symbol not in table:
        return symbol

    index: int = table.index(symbol)

    return table[(index + shift) % len(table)]

@support_hashing
def caesar_shift_sequence(text: T, offset: int, table: A=ALPHABET) -> Generator[S, None, None]:
    """
    Shifts a Sequence by a given offset value.

    Args:
        text (T): The text to shift.
        offset (int): The offset value.
        table (A, optional): The alphabet to use. Defaults to ALPHABET.

    Returns:
        Generator[S, None, None]: The shifted text.
            We use a generator here to allow for lazy evaluation of eg. a stream of characters.
    """

    return (
        shift_symbol(symbol, offset, table)
        for symbol in text
    )

def caesar_encrypt_sequence(text: T, key: int, table: A=ALPHABET) -> Generator[S, None, None]:
    """
    Encrypts a sequence using a Caesar Shift.

    Args:
        text (T): The text to encrypt.
        key (int): The key to use.
        table (A, optional): The alphabet to use. Defaults to ALPHABET.

    Returns:
        Generator[S, None, None]: The encrypted text.
            We use a generator here to allow for lazy evaluation of eg. a stream of characters.
    """

    return caesar_shift_sequence(text, key, table)

def caesar_decrypt_sequence(text: T, key: int, table: A=ALPHABET) -> Generator[S, None, None]:
    """
    Decrypts a sequence using a Caesar Shift.

    Args:
        text (T): The text to decrypt.
        key (int): The key to use.
        table (A, optional): The alphabet to use. Defaults to ALPHABET.

    Returns:
        Generator[S, None, None]: The decrypted text.
            We use a generator here to allow for lazy evaluation of eg. a stream of characters.
    """

    return caesar_shift_sequence(text, -key, table)

@support_hashing
def caesar_encrypt_str(text: str, key: int, table: A=ALPHABET) -> str:
    """
    Encrypts a text using a Caesar Shift.

    Args:
        text (T): The text to encrypt.
        key (int): The key to use.
        table (A, optional): The alphabet to use. Defaults to ALPHABET.

    Returns:
        str: The encrypted text.
    """

    return "".join(
        caesar_encrypt_sequence(text, key, table)
    )

@support_hashing
def caesar_decrypt_str(text: str, key: int, table: A=ALPHABET) -> str:
    """
    Decrypts a text using a Caesar Shift.

    Args:
        text (T): The text to decrypt.
        key (int): The key to use.
        table (A, optional): The alphabet to use. Defaults to ALPHABET.

    Returns:
        str: The decrypted text.
    """

    return "".join(
        caesar_decrypt_sequence(text, key, table)
    )


### Vigenere Cipher
def vigenere_shift_sequence(
        text: T,
        key: T,
        reverse: bool=False,
        table: A=ALPHABET,
        assert_len=False) -> Generator[S, None, None]:
    """
    Shifts a sequence by a given key.

    Args:
        text (T): The text to shift.
        key (T): The key to use.
        table (A, optional): The alphabet to use. Defaults to ALPHABET.

    Returns:
        Generator[S, None, None]: The shifted text.
            We use a generator here to allow for lazy evaluation of eg. a stream of characters.
    """

    # Check if the key is as long as the text if assert_len is True
    # Otherwise, we will just wrap around the key
    assert len(key) == len(text) or not assert_len, \
        "The key must be as long as the text."
    
    return (
        shift_symbol(
            symbol,
            (
                hash_sequence(key[i % len(key)], table)
                * (-1 if reverse else 1)
            ),
            table
        ) for i, symbol in enumerate(text)
    )

def vigenere_encrypt_sequence(text: T, key: T, table: A=ALPHABET) -> Generator[S, None, None]:
    """
    Shifts a sequence by a given key.

    Args:
        text (T): The text to shift.
        key (T): The key to use.
        table (A, optional): The alphabet to use. Defaults to ALPHABET.

    Returns:
        Generator[S, None, None]: The shifted text.
            We use a generator here to allow for lazy evaluation of eg. a stream of characters.
    """

    return vigenere_shift_sequence(
        text=text,
        key=key,
        table=table
    )

def vigenere_decrypt_sequence(text: T, key: T, table: A=ALPHABET) -> Generator[S, None, None]:
    """
    Shifts a sequence by a given key.

    Args:
        text (T): The text to shift.
        key (T): The key to use.
        table (A, optional): The alphabet to use. Defaults to ALPHABET.

    Returns:
        Generator[S, None, None]: The shifted text.
            We use a generator here to allow for lazy evaluation of eg. a stream of characters.
    """

    return vigenere_shift_sequence(
        text=text,
        key=key,
        reverse=True,
        table=table
    )

def vigenere_encrypt_str(text: str, key: str, table: A=ALPHABET) -> str:
    """
    Encrypts a text using a Vigenere Cipher.

    Args:
        text (T): The text to encrypt.
        key (T): The key to use.
        table (A, optional): The alphabet to use. Defaults to ALPHABET.

    Returns:
        str: The encrypted text.
    """

    return "".join(
        vigenere_encrypt_sequence(text, key, table)
    )

def vigenere_decrypt_str(text: str, key: str, table: A=ALPHABET) -> str:
    """
    Decrypts a text using a Vigenere Cipher.

    Args:
        text (T): The text to decrypt.
        key (T): The key to use.
        table (A, optional): The alphabet to use. Defaults to ALPHABET.

    Returns:
        str: The decrypted text.
    """

    return "".join(
        vigenere_decrypt_sequence(text, key, table)
    )


REPLACEMENTS = {
    ' ': '␣',
    '\n': '↵',
    '\t': '⇥',
    '\r': '⇤'
}

# Prettyfying
def prettyfy(text: str) -> str:
    """
    Prettyfies a text.

    Args:
        text (str): The text to prettyfy.

    Returns:
        str: The prettyfied text.
    """

    return ''.join(
        REPLACEMENTS.get(char, char) for char in text
    )


TEST_TEXT = "Hello World!\nThis is a test message.\n\t- 1234567890"


def test_alg(alg_enc: callable, alg_dec: callable, key: T | int, text: str) -> None:
    """
    Tests an algorithm.

    Args:
        alg (callable): The algorithm to test.
        key (T | int): The key to use.
        text (str): The text to encrypt.
    """

    enc = alg_enc(text, key)
    dec = alg_dec(enc, key)

    print(f"Encrypting with key {key}:")
    print(
f"""============ Original ============
{text}
============ Escaped =============
{prettyfy(text)}
=========== Encrypted ============
{prettyfy(enc)}
======= Decrypted Escaped ========
{prettyfy(dec)}
=========== Decrypted ============
{dec}
==================================
""")

# Main
if __name__ == "__main__":
    # Test Caesar Cipher
    print("Caesar Cipher:")

    # Test encrypting a single character
    key_num = 17
    key_str = "ThisIsAKey"

    test_alg(
        alg_enc=caesar_encrypt_str,
        alg_dec=caesar_decrypt_str,
        key=key_num,
        text=TEST_TEXT
    )

    # Test Vigenere Cipher
    print("Vigenere Cipher:")
    test_alg(
        alg_enc=vigenere_encrypt_str,
        alg_dec=vigenere_decrypt_str,
        key=key_str,
        text=TEST_TEXT
    )