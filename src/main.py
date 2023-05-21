#!python3
"""
Graphical User Interface for the application using gi.repository: Gtk+

Use the `ui/main_window.ui` as the UI source file.
"""

# Standard library imports
import os
import string
from typing import Any, Generator, List, Optional
import subprocess

# Get python path site-packages
command = 'python3 -c "import site; print(site.getsitepackages()[0])"'
site_packages = subprocess.check_output(command, shell=True).decode('utf-8').strip()

print(f'Using site-packages: {site_packages}')

# ls the site-packages directory
command = f'ls {site_packages}'
site_packages_ls = subprocess.check_output(command, shell=True).decode('utf-8').strip()

# Check if gi is installed
if 'gi' not in site_packages_ls:
    raise ImportError('gi.repository is not installed')

# Load gi, set the version (3.0) and import Gtk
import sys
sys.path.append(site_packages)

import gi # type: ignore
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, Gdk, GObject # type: ignore
from gi.repository import GdkPixbuf # type: ignore

# Local imports
from encrypt import caesar_encrypt_sequence, caesar_decrypt_sequence
from encrypt import vigenere_encrypt_sequence, vigenere_decrypt_sequence
from break_lib import caesar_guess_alphabet, caesar_guess_shift

# Constants
BYTE_ALPHABET = [
    n for n in range(256)
]

# BYTES, lower, upper, letters, letters and numbers, None
ALPHABETS = {
    '0': BYTE_ALPHABET,
    '1': list(range(97, 123)) + [32],
    '2': list(range(65, 91)) + [32],
    '3': list(range(97, 123)) + list(range(65, 91)) + [32],
    '4': list(range(97, 123)) + list(range(65, 91)) + list(range(48, 58)) + [32],
    '5': list(range(97, 123)) + list(range(65, 91)) + list(range(48, 58)) + list(range(32, 48)),
    '6': None
}

ALGORITHMS = {
    '0': 'caesar',
    '1': 'vigenere'
}

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

    # Non Readable Flag
    non_readable: bool = False

    # Keys generator
    keys: Optional[Generator[str, None, None]]

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

        print('\x1B[35mLoading UI...\x1B[0m', end='', flush=True)

        self.builder.add_from_file(file)

        self.main_window = self.builder.get_object(main_obj)

        # Load window icon from 'ui/Icon.png'
        icon = GdkPixbuf.Pixbuf.new_from_file('ui/Brutus.png')
        self.main_window.set_icon(icon)

        print('\t\x1B[32;1mDone\x1B[0m')

        try:
            self.get_objects()
        except AssertionError as e:
            print(e)
            exit(1)

        # Set data based on default values
        self.update_input()
        self.update_input(False)

        print('\x1B[35mLinking...\x1B[0m', end='', flush=True)

        self.link_file_actions()
        self.link_algorithm_actions()
        self.link_detect_actions()
        self.link_copy_actions()

        print('\t\x1B[32;1mDone\x1B[0m')

        self.apply_algorithm('caesar', BYTE_ALPHABET, '0')

        self.update_text_views()

        # Link close button to quit
        self.main_window.connect('delete-event', Gtk.main_quit)

    def load_file(self, file_path: str, enc: bool=True) -> None:
        print(f'Loading file {file_path}...', end='', flush=True)
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

        print('\t\x1B[32;1mDone\x1B[0m')

    def save_file(self, file_path: str, enc: bool=True) -> None:
        print(f'Saving file {file_path}...', end='', flush=True)
        if enc:
            data: bytes = self.data_enc
        else:
            data: bytes = self.data_dec

        with open(file_path, 'wb') as f:
            f.write(data)

        print(f'\t\x1B[32;1mSaved to {file_path}\x1B[0m')

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
        self.keys = None
        if self.non_readable:
            return

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
                    caesar_decrypt_sequence(used_data, int(key), alphabet) # type: ignore
                )
            else:
                data = bytes(
                    b for b in
                    caesar_encrypt_sequence(used_data, int(key), alphabet) # type: ignore
                )
        elif algorithm == 'vigenere':
            key_vig: List[int] = [
                alphabet.index(ord(c)) if ord(c) in alphabet else 0
                for c in key
            ]

            if self.dec:
                data = bytes(
                    b for b in
                    vigenere_decrypt_sequence(used_data, key_vig, alphabet) # type: ignore
                )
            else:
                data = bytes(
                    b for b in
                    vigenere_encrypt_sequence(used_data, key_vig, alphabet) # type: ignore
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
            
            # If the file is a directory
            if os.path.isdir(file_path):
                # Switch to the directory
                dialog.set_current_folder(file_path)
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

            # If None or file_name_entry is set
            if file_path is None or self.file_name_entry.get_text() != '':
                # Get the directory path
                file_path = dialog.get_current_folder()

                if file_path is None:
                    return

                # Get Content of `file_name_entry`
                file_name = self.file_name_entry.get_text()

                if file_name == '':
                    return

                # Create the file path
                file_path = os.path.join(file_path, file_name)

            # If the path is a directory
            if os.path.isdir(file_path):
                # Switch to the directory
                dialog.set_current_folder(file_path)
                return

            # If the file already exists
            if os.path.exists(file_path):
                # Ask the user if he wants to overwrite the file
                ask_dialog = Gtk.MessageDialog(
                    None,
                    modal=True,
                    message_type=Gtk.MessageType.QUESTION,
                    buttons=Gtk.ButtonsType.YES_NO,
                    text=f'File {file_path} already exists. Do you want to overwrite it?'
                )
                response = ask_dialog.run()
                ask_dialog.destroy()

                if response == Gtk.ResponseType.NO:
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
        # Direction
        self.direction_switch.connect('state-set', self.update_direction)

    def link_detect_actions(self) -> None:
        # Alphabet
        self.alphabet_detect_button.connect('clicked', self.detect_alphabet)
        # Key
        self.key_detect_button.connect('clicked', self.detect_key)

    def link_copy_actions(self) -> None:
        # Copy
        self.copy_dec_button.connect('clicked', self.copy_dec)
        self.copy_enc_button.connect('clicked', self.copy_enc)
        self.clear_dec_button.connect('clicked', self.clear_dec)

    def copy_dec(self, button: Gtk.Button) -> None:
        self.copy(self.decrypted_text_buffer)

    def copy_enc(self, button: Gtk.Button) -> None:
        self.copy(self.encrypted_text_buffer)

    def copy(self, buffer: Gtk.TextBuffer) -> None:
        # Get the clipboard
        clipboard = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)

        # Get the text
        text = buffer.get_text(
            buffer.get_start_iter(),
            buffer.get_end_iter(),
            True
        )

        # Set the clipboard text
        clipboard.set_text(text, -1)

    def clear_dec(self, button: Gtk.Button) -> None:
        self.data_dec = b''
        self.hex_dec = ''
        self.text_dec = ''
        self.decrypted_text_buffer.set_text('')
        self.apply_algorithm(self.algorithm, self.alphabet, self.key)
        self.update_text_views()

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
        
        if self.keys is None:
            # Get the text
            text: str = self.text_enc if self.dec else self.text_dec

            # Detect the key
            self.keys = caesar_guess_shift(
                text=text,
                lang='en',
                min_shift=0,
                max_shift=255,
                alphabet=[
                    chr(i) for i in self.alphabet
                ]
            ) # type: ignore
        
        key: int = next(self.keys, 0) # type: ignore

        if key == 0:
            self.keys = None
                
        # Set the key
        self.key_entry.set_text(str(key))

        # Apply the algorithm
        self.apply_algorithm(self.algorithm, self.alphabet, str(key))

        # Update the view
        self.update_text_views()

    def update_direction(self, switch: Gtk.Switch, state: bool) -> None:
        self.update_text_views()
        self.keys = None

    def update_text_views(self) -> None:
        self.update_view(not self.dec, False)
        self.update_view(not self.dec, True)
        self.update_view(self.dec, True)

        # Set non active text view to non editable and active to editable
        self.decrypted_text_view.set_editable(not self.dec)
        self.encrypted_text_view.set_editable(self.dec)

        # Make the cursor visible in the active text view and invisible in the non active
        self.decrypted_text_view.set_cursor_visible(not self.dec)
        self.encrypted_text_view.set_cursor_visible(self.dec)

        # Update the readable text
        self.update_readable_text()

    def update_readable_text(self) -> None:
        # Get the text for the active text view
        text = self.text_enc if self.dec else self.text_dec

        target = self.decrypted_text_view if not self.dec else self.encrypted_text_view

        # Check if the text is printable/readable
        if any(
            char not in string.printable
            for char in text
        ):
            # Make the text view non editable and cursor invisible
            target.set_editable(False)
            target.set_cursor_visible(False)
            self.non_readable = True
        else:
            # Make the text view editable and cursor visible
            target.set_editable(True)
            target.set_cursor_visible(True)
            self.non_readable = False

    def update_algorithm(self, combo: Gtk.ComboBox) -> None:
        self.keys = None

        # Apply the algorithm
        self.apply_algorithm(self.algorithm, self.alphabet, self.key)

        # Update the view
        self.update_text_views()

    def update_alphabet(self, combo: Gtk.ComboBox) -> None:
        self.keys = None

        # Get the alphabet
        alphabet: List[int] = self.alphabet

        # Apply the algorithm
        self.apply_algorithm(self.algorithm, alphabet, self.key)

        # Update the view
        self.update_text_views()

    def update_key(self, entry: Gtk.Entry) -> None:
        self.keys = None
        
        # Get the key
        key: str = entry.get_text()

        # Apply the algorithm
        self.apply_algorithm(self.algorithm, self.alphabet, key)

        # Update the view
        self.update_text_views()

    def update_text(self, buffer: Gtk.TextBuffer) -> None:
        self.keys = None

        # Update input
        self.update_input(self.dec)

        # Apply the algorithm
        self.apply_algorithm(self.algorithm, self.alphabet, self.key)

        # Update the view
        self.update_text_views()

    def __beautify_ascii(self, text: str) -> str:
        # Check if there are non-readable characters
        if any(
            c not in string.printable
            for c in text
        ):
            return 'Non-readable characters\nLook at the hex view'
        
        # Return the text
        return text
    
    def __debeautify_ascii(self, text: str) -> str:
        # Return the text
        return text

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
        ### File Name Entry
        self.file_name_entry = self.builder.get_object('file_name_entry')
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
            self.open_file_selector_action,
            self.open_ok_button,
            self.save_file_button,
            self.save_file_dialog,
            self.save_is_encrypted_combo,
            self.save_is_encrypted_entry,
            self.open_file_save_action,
            self.save_ok_button,
            self.file_name_entry
        ], 'Failed to get the file controls'

        ## Copy Buttons
        self.copy_dec_button = self.builder.get_object('copy_dec_button')
        self.copy_enc_button = self.builder.get_object('copy_enc_button')
        self.clear_dec_button = self.builder.get_object('clear_dec_button')

        assert None not in [
            self.copy_dec_button,
            self.copy_enc_button,
            self.clear_dec_button
        ], 'Failed to get the copy buttons'

    def show(self) -> None:
        self.main_window.show_all()

if __name__ == '__main__':
    # Disable header bar warning
    Gtk.Settings.get_default().set_property('gtk-decoration-layout', 'menu:close')

    app: Application

    # Test if run' from pyinstaller one-file bundle
    if getattr(sys, 'frozen', False):
        # Change working directory to the bundle resource path
        os.chdir(sys._MEIPASS) # type: ignore
    else:
        # Get file directory
        os.chdir(os.path.dirname(os.path.realpath(__file__)))
        os.chdir('..')

    app = Application('ui/main.ui')

    print('\x1B[32;1mShowing UI!\x1B[0m')

    app.show()

    # Wait for the window to close
    Gtk.main()