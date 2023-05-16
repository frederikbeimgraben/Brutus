#!/usr/bin/env python3
"""
Attempt to break the caesar cipher in encrypt.py.

Author: Frederik Beimgraben (github/frederikbeimgraben)
Created: 2023-05-16

Use typical frequency analysis to break the caesar cipher.
"""

# Standard imports
from typing import Dict, Generator, List, Tuple
import json

# Local imports
from encrypt import caesar_decrypt_str, caesar_encrypt_str, TEST_TEXT, prettyfy
from parallel_stream import async_map

LANGUAGE = "en"

# Source: https://en.wikipedia.org/wiki/Letter_frequency
FREQUENCIES = {
    "en": {
        "a": 8.167,
        "b": 1.492,
        "c": 2.782,
        "d": 4.253,
        "e": 12.702,
        "f": 2.228,
        "g": 2.015,
        "h": 6.094,
        "i": 6.966,
        "j": 0.153,
        "k": 0.772,
        "l": 4.025,
        "m": 2.406,
        "n": 6.749,
        "o": 7.507,
        "p": 1.929,
        "q": 0.095,
        "r": 5.987,
        "s": 6.327,
        "t": 9.056,
        "u": 2.758,
        "v": 0.978,
        "w": 2.360,
        "x": 0.150,
        "y": 1.974,
        "z": 0.074,
    }
}

DICTIONARIES = {
    "en": "dicts/en.json"
}

def get_frequencies(language: str) -> Dict[str, float]:
    """
    Returns the frequencies for the given language.

    Raises a ValueError if the language is not supported.

    Args:
        language (str): The language to get the frequencies for.

    Returns:
        Dict[str, float]: The frequencies for the given language.
    """
    if language not in FREQUENCIES:
        raise ValueError(f"Language {language} is not supported.")

    return FREQUENCIES[language]

def get_words(language: str) -> List[str]:
    """
    Returns the words for the given language.

    Raises a ValueError if the language is not supported.

    Args:
        language (str): The language to get the words for.

    Returns:
        List[str]: The words for the given language.
    """
    if language not in DICTIONARIES:
        raise ValueError(f"Language {language} is not supported.")

    # Load the dictionary
    # {
    #     <word>: <description>,
    #     ...
    # }
    with open(DICTIONARIES[language], "r") as file:
        dictionary = json.load(file)

    return [
        word.replace("a ", "").lower()
        for word in dictionary
    ]

def calculate_text_frequencies(
        text: str,
        language: str) -> Dict[str, Dict[str, List[int] | float]]:
    """
    Calculates the frequencies of the given text.

    Args:
        text (str): The text to calculate the frequencies for.
        language (str): The language to use for the frequencies.

    Returns:
        Dict[str, Dict[str, List[int] | float]]: {
            <letter>: {
                "indices": List[int],
                "frequency": float
            },
            ...
        }
        -> The frequencies of the given text.
    """

    frequencies = {
        letter: {
            "indices": [],
            "frequency": 0.0
        }
        for letter in get_frequencies(LANGUAGE)
    }

    for index, letter in enumerate(text):
        if letter in frequencies:
            frequencies[letter]["indices"].append(index)

    for letter, data in frequencies.items():
        data["frequency"] = len(data["indices"]) / len(text)

    return frequencies

# Guess the key by finding the most common letters in the text and test their shifts
def guess_key(
        text: str,
        language: str,
        top: int = 5) -> Generator[int, None, None]:
    """
    Guesses the key for the given text.

    Args:
        text (str): The text to guess the key for.
        language (str): The language to use for the frequencies.
        top (int, optional): The number of top letters to use for guessing the key. Defaults to 5.

    Yields:
        Generator[int, None, None]: The guessed keys.
    """

    # Get the frequencies of the text
    frequencies = calculate_text_frequencies(text, language)

    # Sort the frequencies
    sorted_frequencies = sorted(
        frequencies.items(),
        key=lambda item: item[1]["frequency"],
        reverse=True
    )

    # Get the top letters
    top_letters = [
        letter
        for letter, data in sorted_frequencies[:top]
    ]

    # Get the frequencies of the language
    language_frequencies = get_frequencies(language)

    # Get the frequencies of the top letters
    top_letter_frequencies = {
        letter: language_frequencies[letter]
        for letter in top_letters
    }

    # Get the shifts
    shifts = [
        ord(letter) - ord("e")
        for letter in top_letters
    ]

    # Yield the shifts
    for shift in shifts:
        yield shift

def guess_text(
        text: str,
        language: str,
        top: int = 5) -> str:
    """
    Guesses the text for the given text.

    Args:
        text (str): The text to guess the text for.
        language (str): The language to use for the frequencies.
        top (int, optional): The number of top letters to use for guessing the key. Defaults to 5.

    Yields:
        Generator[str, None, None]: The guessed texts.
    """

    # Load the words
    words = get_words(language)

    @async_map(
        max_workers=10,
        wait=False,
        timeout=10,
    )
    def guess_key_text(
            key: int) -> Tuple[Tuple[int, int], str]:
        """
        Gets the number of valid words for the given key.
        """

        return len([
            word
            for word in caesar_decrypt_str(text, key).split(" ")
            if word.lower().strip('. !?,') in words
        ]), key

    # Find the key producing the most valid words
    guesses = list(
        guess_key_text(
            guess_key(
                text,
                language,
                top
            )
        )
    )

    # Sort the guesses
    sorted_guesses = sorted(
        guesses,
        key=lambda item: item[0],
        reverse=True
    )
    

    # Get the best guess
    best_guess = sorted_guesses[0]

    # Return the decrypted text
    return best_guess, caesar_decrypt_str(text, best_guess[1])
    

KEY = 17

if __name__ == "__main__":
    # Test the guess text function
    text = "This is a test."
    language = "en"
    top = 10

    print(
f"""\x1B[32m==============\x1B[1mORIGINAL\x1B[0;32m=============\x1B[0m
{text}
\x1B[32m===================================\x1B[0m
"""
    )

    enc = caesar_encrypt_str(text, KEY)
    print(
f"""\x1B[32m=============\x1B[1mENCRYPTED\x1B[0;32m=============\x1B[0m
{prettyfy(enc)}
\x1B[32m===================================\x1B[0m
"""
    )
    print(f"\x1B[32;1mActual Key:\x1B[0m {KEY}")

    print("\x1B[32;1mGuessing text...\x1B[0m")
    (occ, key), guess = guess_text(enc, language, top)
    print(
f"""\x1B[32m===============\x1B[1mGUESS\x1B[0;32m===============\x1B[0m
{guess}
\x1B[32m===================================\x1B[0m
"""
    )
    print(f"\x1B[32;1mGuess Key:\x1B[0m {key}")
    print(f"\x1B[32;1mValid Words:\x1B[0m {occ}")
