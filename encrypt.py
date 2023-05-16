"""
Encryption Algorithms for the project

Author:  Frederik Beimgraben (github/frederikbeimgraben)
Created: 2023/05/16

Contains:
    - Simple Caesar Shift
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
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890 !?."


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
    if symbol not in table.values():
        return symbol

    index: int = table.invert[symbol]

    return table[(index + shift) % len(table)]

@support_hashing
def shift_sequence(text: T, offset: int, table: A=ALPHABET) -> Generator[S, None, None]:
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