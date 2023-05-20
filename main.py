"""
Graphical User Interface for the application using gi.repository: Gtk+

Use the `ui/main_window.ui` as the UI source file.
"""

# Standard library imports
import os
import sys
from typing import Any, List

# Third party imports
import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, Gio, Gdk, GLib

# Local imports
from encrypt import caesar_encrypt_sequence, caesar_decrypt_sequence, S, T, A
from encrypt import vigenere_encrypt_sequence, vigenere_decrypt_sequence
from break_lib import caesar_break, caesar_guess_alphabet, caesar_guess_shift
from encrypt_file import apply_file

# Constants
BYTE_ALPHABET = [
    n for n in range(256)
]

# BYTES, lower, upper, letters, letters and numbers, None
ALPHABETS = {
    '0': BYTE_ALPHABET,
    '1': list(range(97, 123)),
    '2': list(range(65, 91)),
    '3': list(range(97, 123)) + list(range(65, 91)),
    '4': list(range(97, 123)) + list(range(65, 91)) + list(range(48, 58)),
    '5': list(range(97, 123)) + list(range(65, 91)) + list(range(48, 58)) + list(range(32, 48)),
    '6': None
}

ALGORITHMS = {
    '0': 'caesar',
    '1': 'vigenere'
}

BEAUTIFY_REPLACE = {
    '\x00': '␀',
    '\x01': '␁',
    '\x02': '␂',
    '\x03': '␃',
    '\x04': '␄',
    '\x05': '␅',
    '\x06': '␆',
    '\x07': '␇',
    '\x08': '␈',
    '\x09': '␉',
    '\x0A': '␊',
    '\x0B': '␋',
    '\x0C': '␌',
    '\x0D': '␍',
    '\x0E': '␎',
    '\x0F': '␏',
    '\x10': '␐',
    '\x11': '␑',
    '\x12': '␒',
    '\x13': '␓',
    '\x14': '␔',
    '\x15': '␕',
    '\x16': '␖',
    '\x17': '␗',
    '\x18': '␘',
    '\x19': '␙',
    '\x1A': '␚',
    '\x1B': '␛',
    '\x1C': '␜',
    '\x1D': '␝',
    '\x1E': '␞',
    '\x1F': '␟',
    '\x7F': '␡',
}

DEBEAUTIFY = {v: k for k, v in BEAUTIFY_REPLACE.items()}

# GUI
## Main window
class Application():
    builder: Gtk.Builder
    main_window: Any

    # Text views
    text_dec: str 
    text_enc: str
    data_dec: bytes
    data_enc: bytes
    hex_dec: str
    hex_enc: str

    # Update counter
    last_text: str = ''

    # Alphabet
    @property
    def alphabet(self) -> List[int]:
        alphabet_id = self.alphabet_combo.get_active_id()
        alphabet = ALPHABETS[alphabet_id]

        if alphabet is None:
            # Get custom alphabet
            alphabet = self.custom_alphabet_entry.get_text()
            alphabet = [ord(c) for c in alphabet]
        else:
            alphabet = alphabet.copy()
        
        return alphabet
    
    @property
    def algorithm(self) -> str:
        algorithm_id = self.algorithm_combo.get_active_id()
        algorithm = ALGORITHMS[algorithm_id]

        return algorithm
    
    @property
    def key(self) -> str:
        return self.key_entry.get_text()
    
    @property
    def dec(self) -> bool:
        return self.direction_switch.get_active()

    def __init__(self, file: str, main_obj: str='main_window') -> None:
        self.builder = Gtk.Builder()
        self.builder.add_from_file(file)

        self.main_window = self.builder.get_object(main_obj)

        try:
            self.get_objects()
        except AssertionError as e:
            print(e)
            sys.exit(1)

        # Set data based on default values
        self.update_input()
        self.update_input(False)

        self.link_file_actions()
        self.link_algorithm_actions()
        self.link_detect_actions()

        self.apply_algorithm('caesar', BYTE_ALPHABET, '0')

        self.update_text_views()

    def load_file(self, file_path: str, enc: bool=True) -> None:
        with open(file_path, 'rb') as f:
            data: bytes = f.read()

        text: str = ''.join(
            chr(b) for b in data
        )
        hex: str = ' '.join(
            [f'{b:02X}' for b in data]
        )

        if enc:
            self.text_enc = text
            self.data_enc = data
            self.hex_enc = hex
        else:
            self.text_dec = text
            self.data_dec = data
            self.hex_dec = hex

    def save_file(self, file_path: str, enc: bool=True) -> None:
        if enc:
            data: bytes = self.data_enc
        else:
            data: bytes = self.data_dec

        with open(file_path, 'wb') as f:
            f.write(data)

        print(f'File saved to {file_path}')

    def update_view(self, enc: bool=True, hex: bool=True) -> None:
        if enc:
            if hex:
                self.encrypted_hex_buffer.set_text(
                    self.hex_enc
                )
            else:
                self.encrypted_text_buffer.set_text(
                    self.__beautify_ascii(self.text_enc)
                )
        else:
            if hex:
                self.decrypted_hex_buffer.set_text(
                    self.hex_dec
                )
            else:
                self.decrypted_text_buffer.set_text(
                    self.__beautify_ascii(self.text_dec)
                )

    def update_input(self, enc: bool=True) -> None:
        if enc:
            self.text_enc = self.__debeautify_ascii(
                self.encrypted_text_buffer.get_text(
                    self.encrypted_text_buffer.get_start_iter(),
                    self.encrypted_text_buffer.get_end_iter(),
                    True
                )
            )
            self.data_enc = self.text_enc.encode()
            hex_enc = ' '.join(
                [f'{b:02X}' for b in self.data_enc]
            )
        else:
            self.text_dec = self.__debeautify_ascii(
                self.decrypted_text_buffer.get_text(
                    self.decrypted_text_buffer.get_start_iter(),
                    self.decrypted_text_buffer.get_end_iter(),
                    True
                )
            )
            self.data_dec = self.text_dec.encode()
            self.hex_dec = ' '.join(
                [f'{b:02X}' for b in self.data_dec]
            )

    def apply_algorithm(self, algorithm: str, alphabet: List[int], key: str) -> None:
        if self.dec:
            data: bytes = self.data_enc
        else:
            data: bytes = self.data_dec

        used_data: List[int] = [
            b for b in data
        ]

        if key == '':
            if algorithm == 'caesar':
                key = '0'
            elif algorithm == 'vigenere':
                key = chr(alphabet[0])

        if algorithm == 'caesar':
            try:
                int(key)
            except ValueError:
                return
            
            if self.dec:
                data = bytes(
                    b for b in
                    caesar_decrypt_sequence(used_data, int(key), alphabet)
                )
            else:
                data = bytes(
                    b for b in
                    caesar_encrypt_sequence(used_data, int(key), alphabet)
                )
        elif algorithm == 'vigenere':
            key_vig: List[int] = [
                alphabet.index(ord(c)) if ord(c) in alphabet else 0
                for c in key
            ]

            if self.dec:
                data = bytes(
                    b for b in
                    vigenere_decrypt_sequence(used_data, key_vig, alphabet)
                )
            else:
                data = bytes(
                    b for b in
                    vigenere_encrypt_sequence(used_data, key_vig, alphabet)
                )
        else:
            raise ValueError(f'Unknown algorithm: {algorithm}')

        text: str = ''.join(
            chr(b) for b in data
        )
        data: bytes = data
        hex: str = ' '.join(
            [f'{b:02X}' for b in data]
        )

        if self.dec:
            self.text_dec = text
            self.data_dec = data
            self.hex_dec = hex
        else:
            self.text_enc = text
            self.data_enc = data
            self.hex_enc = hex

    def open_file_dialog_response(self, dialog, response_id):
        if response_id == Gtk.ResponseType.OK:
            # Get the file path
            file_path = dialog.get_filename()

            # Get state of combo 'is encrypted'
            is_encrypted = self.open_is_encrypted_combo.get_active_id() != '0'

            # Flip direction switch to is_encrypted
            self.direction_switch.set_active(is_encrypted)

            if file_path is None:
                return

            # Load the file
            self.load_file(file_path, enc=is_encrypted)

            # Apply Algorithm
            self.apply_algorithm(self.algorithm, self.alphabet, self.key)

            # Update the views
            [
                self.update_view(i, j)
                for i in [True, False]
                for j in [True, False]
            ]

        # Hide the dialog
        dialog.hide()

    def save_file_dialog_response(self, dialog, response_id):
        if response_id == Gtk.ResponseType.OK:
            # Get the file path
            file_path = dialog.get_filename()

            # Get state of combo 'is encrypted'
            is_encrypted = self.save_is_encrypted_combo.get_active_id() != 0

            if file_path is None:
                return

            # Save the file
            self.save_file(file_path, enc=is_encrypted)

        # Hide the dialog
        dialog.hide()

    def link_file_actions(self) -> None:
        # Open File
        self.open_file_dialog.connect('response', self.open_file_dialog_response)
        self.open_file_button.connect('clicked', lambda _: self.open_file_dialog.show())
        ## Buttons
        self.open_ok_button.connect('clicked', lambda _: self.open_file_dialog_response(self.open_file_dialog, Gtk.ResponseType.OK))
        self.open_close_button.connect('clicked', lambda _: self.open_file_dialog_response(self.open_file_dialog, Gtk.ResponseType.CANCEL))

        # Save File
        self.save_file_dialog.connect('response', self.save_file_dialog_response)
        self.save_file_button.connect('clicked', lambda _: self.save_file_dialog.show())
        ## Buttons
        self.save_ok_button.connect('clicked', lambda _: self.save_file_dialog_response(self.save_file_dialog, Gtk.ResponseType.OK))
        self.save_close_button.connect('clicked', lambda _: self.save_file_dialog_response(self.save_file_dialog, Gtk.ResponseType.CANCEL))

    def link_algorithm_actions(self) -> None:
        """
        The Algorithm should be applied upon:
            - Changing the algorithm
            - Changing the alphabet
            - Changing the key
            - Changing the text

        The algorithm should be applied based on:
            - Direction button
        """

        # Algorithm
        self.algorithm_combo.connect('changed', self.update_algorithm)
        # Alphabet
        self.alphabet_combo.connect('changed', self.update_alphabet)
        self.custom_alphabet_entry.connect('changed', self.update_alphabet)
        # Key
        self.key_entry.connect('changed', self.update_key)
        # Text (connect to the text view and not the buffer)
        self.decrypted_text_buffer.connect('end_user_action', self.update_text)
        self.encrypted_text_buffer.connect('end_user_action', self.update_text)

    def link_detect_actions(self) -> None:
        # Alphabet
        self.alphabet_detect_button.connect('clicked', self.detect_alphabet)
        # Key
        self.key_detect_button.connect('clicked', self.detect_key)

    def detect_alphabet(self, button: Gtk.Button) -> None:
        if self.algorithm != 'caesar':
            return

        # Get the text
        text = self.text_enc if self.dec else self.text_dec

        # Detect the alphabet
        alphabet: str = caesar_guess_alphabet(text)

        # Set alphabet combo to 'Custom' (id: 5)
        self.alphabet_combo.set_active_id(alphabet)

    def detect_key(self, button: Gtk.Button) -> None:
        if self.algorithm != 'caesar':
            return
        if not self.dec:
            return

        # Get the text
        text: str = self.text_enc if self.dec else self.text_dec

        # Detect the key
        key: int = next(caesar_guess_shift(
            text=text,
            lang='en',
            min_shift=0,
            max_shift=255,
            alphabet=[
                chr(i) for i in self.alphabet
            ]
        ))

        # Set the key
        self.key_entry.set_text(str(key))

        # Apply the algorithm
        self.apply_algorithm(self.algorithm, self.alphabet, str(key))

        # Update the view
        self.update_text_views()

    def update_text_views(self) -> None:
        self.update_view(not self.dec, False)
        self.update_view(not self.dec, True)
        self.update_view(self.dec, True)

    def update_algorithm(self, combo: Gtk.ComboBox) -> None:
        # Apply the algorithm
        self.apply_algorithm(self.algorithm, self.alphabet, self.key)

        # Update the view
        self.update_text_views()

    def update_alphabet(self, combo: Gtk.ComboBox) -> None:
        # Get the alphabet
        alphabet: List[int] = self.alphabet

        # Apply the algorithm
        self.apply_algorithm(self.algorithm, alphabet, self.key)

        # Update the view
        self.update_text_views()

    def update_key(self, entry: Gtk.Entry) -> None:
        # Get the key
        key: str = entry.get_text()

        # Apply the algorithm
        self.apply_algorithm(self.algorithm, self.alphabet, key)

        # Update the view
        self.update_text_views()

    def update_text(self, buffer: Gtk.TextBuffer) -> None:        
        # Update input
        self.update_input(self.dec)

        # Apply the algorithm
        self.apply_algorithm(self.algorithm, self.alphabet, self.key)

        # Update the view
        self.update_text_views()

    def __beautify_ascii(self, text: str) -> str:
        return ''.join(
            BEAUTIFY_REPLACE.get(c, c)
            for c in text
        )
    
    def __debeautify_ascii(self, text: str) -> str:
        return ''.join(
            DEBEAUTIFY.get(c, c)
            for c in text
        )

    def get_objects(self) -> None:
        # Get the objects
        ## Decrypted text view
        self.decrypted_text_view = self.builder.get_object('text_dec_box')
        self.decrypted_text_buffer = self.builder.get_object('text_dec')
        self.decrypted_hex_view = self.builder.get_object('hex_dec_box')
        self.decrypted_hex_buffer = self.builder.get_object('hex_dec')
        ## Encrypted text view
        self.encrypted_text_view = self.builder.get_object('text_enc_box')
        self.encrypted_text_buffer = self.builder.get_object('text_enc')
        self.encrypted_hex_view = self.builder.get_object('hex_enc_box')
        self.encrypted_hex_buffer = self.builder.get_object('hex_enc')

        assert None not in [
            self.decrypted_text_view,
            self.decrypted_text_buffer,
            self.decrypted_hex_view,
            self.decrypted_hex_buffer,
            self.encrypted_text_view,
            self.encrypted_text_buffer,
            self.encrypted_hex_view,
            self.encrypted_hex_buffer
        ], 'Failed to get the text views'

        ## Controls
        ### Algorithm
        self.algorithm_combo = self.builder.get_object('algorithm_combo')
        self.algorithm_entry = self.builder.get_object('algorithm_entry')
        ### Alphabet
        self.alphabet_combo = self.builder.get_object('alphabet_combo')
        self.alphabet_entry = self.builder.get_object('alphabet_entry')
        ### Key
        self.key_entry = self.builder.get_object('key_entry')
        ### Detect Buttons (key and alphabet)
        self.key_detect_button = self.builder.get_object('key_detect_button')
        self.alphabet_detect_button = self.builder.get_object('alphabet_detect_button')
        ### Direction Switch
        self.direction_switch = self.builder.get_object('direction_switch')
        ### Custom alphabet entry
        self.custom_alphabet_entry = self.builder.get_object('custom_alphabet_entry')

        assert None not in [
            self.algorithm_combo,
            self.algorithm_entry,
            self.alphabet_combo,
            self.alphabet_entry,
            self.key_entry,
            self.key_detect_button,
            self.alphabet_detect_button,
            self.direction_switch
        ], 'Failed to get the controls'

        ## Open/Save File and Mode selection
        ### Open File
        self.open_file_button = self.builder.get_object('open_file_button')
        self.open_file_dialog = self.builder.get_object('open_file_dialog')
        #### Mode Selection
        self.open_is_encrypted_combo = self.builder.get_object('open_is_encrypted_combo')
        self.open_is_encrypted_entry = self.builder.get_object('open_is_encrypted_entry')
        self.open_format_combo = self.builder.get_object('open_format_combo')
        self.open_format_entry = self.builder.get_object('open_format_entry')
        #### Actions
        self.open_file_selector_action = self.builder.get_object('open_file_save_action')
        #### Buttons
        self.open_ok_button = self.builder.get_object('open_ok_button')
        self.open_close_button = self.builder.get_object('open_close_button')
        ### Save File
        self.save_file_button = self.builder.get_object('save_file_button')
        self.save_file_dialog = self.builder.get_object('save_file_dialog')
        #### Mode Selection
        self.save_is_encrypted_combo = self.builder.get_object('save_is_encrypted_combo')
        self.save_is_encrypted_entry = self.builder.get_object('save_is_encrypted_entry')
        self.save_format_combo = self.builder.get_object('save_format_combo')
        self.save_format_entry = self.builder.get_object('save_format_entry')
        #### Actions
        self.open_file_save_action = self.builder.get_object('open_file_save_action')
        #### Buttons
        self.save_ok_button = self.builder.get_object('save_ok_button')
        self.save_close_button = self.builder.get_object('save_close_button')

        assert None not in [
            self.open_file_button,
            self.open_file_dialog,
            self.open_is_encrypted_combo,
            self.open_is_encrypted_entry,
            self.open_format_combo,
            self.open_format_entry,
            self.open_file_selector_action,
            self.open_ok_button,
            self.save_file_button,
            self.save_file_dialog,
            self.save_is_encrypted_combo,
            self.save_is_encrypted_entry,
            self.save_format_combo,
            self.save_format_entry,
            self.open_file_save_action,
            self.save_ok_button,
        ], 'Failed to get the file controls'

    def show(self) -> None:
        self.main_window.show_all()

if __name__ == '__main__':
    app = Application('ui/main.ui')

    app.show()

    # Wait for the window to close
    Gtk.main()