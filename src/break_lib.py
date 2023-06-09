"""
Functions for breaking caesar and vigenere ciphers.

Author: Frederik Beimgraben (github/frederikbeimgraben)
Created: 2023-05-19

Frequencies and wordlists are saved in `dicts/<lang>/words.json` and `dicts/<lang>/freqs.json`.
`words.json`: {
    <word>: <definition>
}

`freqs.json`: {
    'letters': {
        <letter>: <frequency>
    },
    'word_len': <average word length>
}
"""

import string
import operator
import json

from typing import Generator, List, Optional, Tuple

# Local imports
from encrypt import caesar_decrypt_sequence
from parallel_stream import async_map

# Constants
DEFAULT_ALPHABET: str = ''.join(
    chr(i)
    for i in range(0, 256)
)

# Language loading
langs = {
    'en'
}

def load_words(lang):
    """
    Load words from `dicts/<lang>/words.json`.
    """
    with open(f'dicts/{lang}/words.json', 'rb') as file:
        return json.load(file)

def load_freqs(lang):
    """
    Load frequencies from `dicts/<lang>/freqs.json`.
    """
    with open(f'dicts/{lang}/freqs.json', 'rb') as file:
        return json.load(file)

# Guessers
## Caesar
### Shift
def caesar_guess_shift(
        text: str,
        lang: str,
        min_shift: int = 0,
        max_shift: int = 26,
        alphabet: str | List[str] = DEFAULT_ALPHABET) -> Generator[int, None, None]:
    """
    Guess the shift of a caesar cipher.

    Args:
        text (str): The text to guess the shift of.
        lang (str): The language of the text.
        min_shift (int, optional): The minimum shift to try. Defaults to 0.
        max_shift (int, optional): The maximum shift to try. Defaults to 26.
        alphabet (str, optional): The alphabet to use. Defaults to string.ascii_lowercase.

    Returns:
        Iterable[int]: The guessed shifts in order of probability.
    """

    assert ' ' in alphabet, 'Alphabet must contain space'

    # Load frequencies
    freqs = load_freqs(lang)

    # Get the shifts (distance from space in alphabet)
    shifts = (
        (alphabet.index(char) - alphabet.index(' ')) % len(alphabet)
        for char, _ in sorted(
            (
                (
                    char,
                    sum(
                        (len(word) - freqs['word_len']) ** 2
                        for word in text.split(char)
                    )
                ) for char in alphabet
            ),
            key=operator.itemgetter(1)
        )
    )

    # Filter out shifts that are not in range
    shifts = (
        shift
        for shift in shifts
        if min_shift <= shift <= max_shift
    )

    return shifts


### Alphabet
def caesar_guess_alphabet(
        text: str) -> str:
    """
    Guess the alphabet of a caesar cipher.
    Do this by the characters contained in the text.
        only lowercase letters -> lowercase alphabet
        only uppercase letters -> uppercase alphabet
        only ascii letters -> ascii letters
        only ascii letters and numbers -> ascii letters and numbers
        only ascii letters, numbers and punctuation -> ascii letters, numbers and punctuation
        various ascii characters -> ascii characters
    
    Args:
        text (str): The text to guess the alphabet of.

    Returns:
        Iterable[str]: The guessed alphabet.
    """

    # Create a set of all characters in the text
    chars = set(text)

    # Remove spaces
    chars.discard(' ')

    # Select the alphabet based on the characters
    if chars <= set(string.ascii_lowercase):
        return '1'
    elif chars <= set(string.ascii_uppercase):
        return '2'
    elif chars <= set(string.ascii_letters):
        return '3'
    elif chars <= set(string.ascii_letters + string.digits):
        return '4'
    elif chars <= set(string.ascii_letters + string.digits + string.punctuation):
        return '5'
    else:
        return '0'

def caesar_break(
        text: str,
        lang: str='en',
        alphabet: Optional[str]=None) -> int:
    """
    Break a caesar cipher.

    Args:
        text (str): The text to break.
        lang (str, optional): The language of the text. Defaults to 'en'.
        alphabet (str, optional): The alphabet to use. Defaults to None.

    Returns:
        Tuple[int, str, str]: The shift, alphabet and decrypted text.

    Raises:
        ValueError: Wrong language.
    """

    if lang not in langs:
        raise ValueError(f'Wrong language: {lang}')

    # Guess the alphabet
    if alphabet is None:
        alphabet = ''.join(
            str(c) for c in
            caesar_guess_alphabet(text)
        )

    # Guess the shift
    shifts = caesar_guess_shift(text, lang, alphabet=alphabet)

    # Decrypt the text
    @async_map(max_workers=4, wait=False)
    def guess_text_with_words(
        shift: int) -> Tuple[int, int]:
        """
        Guess the text with a given shift.
        """

        # Decrypt the text
        # Ignore pylance type issue
        # pylint: disable=unsubscriptable-object
        decrypted = ''.join(
            str(c) for c in
            caesar_decrypt_sequence(text, shift, table=alphabet) # type: ignore
        )

        # Split the text into words
        words = decrypted.split(' ')

        # Count the number of words in the dictionary
        num_words = sum(
            1
            for word in words
            if word in words
        )

        # Return the number of words
        return shift, num_words

    # Get the number of words for each shift
    num_words = list(guess_text_with_words(shifts))          # type: ignore
    num_words.sort(key=operator.itemgetter(1), reverse=True) # type: ignore

    # Return the best shift
    return num_words[0]
