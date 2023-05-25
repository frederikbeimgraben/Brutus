#!python3
"""
Graphical User Interface for the application using gi.repository: Gtk+

Use the `ui/main_window.ui` as the UI source file.
"""

# Standard library imports
import os
import random
import string
from typing import Any, Generator, List, Optional, Dict, Tuple
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
from encrypt import vigenere_encrypt_sequence, vigenere_decrypt_sequence, vigenere_break_vari
from encrypt import enigma_decrypt_sequence, enigma_encrypt_sequence, BYTE_ROTORS, EnigmaRotor
from break_lib import caesar_guess_alphabet, caesar_guess_shift

# Constants
BYTE_ALPHABET: List[int] = [
    n for n in range(256)
]

# BYTES, lower, upper, letters, letters and numbers, None
ALPHABETS: Dict[str, List[int] | None] = {
    '0': BYTE_ALPHABET,
    '1': list(range(97, 123)) + [32],
    '2': list(range(65, 91)) + [32],
    '3': list(range(97, 123)) + list(range(65, 91)) + [32],
    '4': list(range(97, 123)) + list(range(65, 91)) + list(range(48, 58)) + [32],
    '5': list(range(97, 123)) + list(range(65, 91)) + list(range(48, 58)) + list(range(32, 48)),
    '6': None
}

# Create new rotors for each alphabet
pseudo_random = random.Random(0)
ROTORS: Dict[str, List[EnigmaRotor]] = {
    alphabet_id: [
        EnigmaRotor(
            alphabet=alphabet,
            position=pseudo_random.randint(0, 255),
            mapping=pseudo_random.sample(alphabet, len(alphabet))
        ) for _ in range(5)
    ]
    for alphabet_id, alphabet in ALPHABETS.items()
    if alphabet is not None
}

ALGORITHMS: Dict[str, str] = {
    '0': 'caesar',
    '1': 'vigenere',
    '2': 'enigma'
}

UNREADABLE_TABLE: Dict[str, str] = {
    'ü': 'ue',
    'ä': 'ae',
    'ö': 'oe',
    'ß': 'ss'
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

        if alphabet_id == '6':
            if self.algorithm == 'enigma':
                self.algorithm_combo.set_active_id('0')

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
    def key(self) -> str | int | Tuple[Tuple[int, ...], Tuple[EnigmaRotor, ...]]:
        if self.algorithm == 'vigenere':
            return self.key_buffer.get_text()
        elif self.algorithm == 'caesar':
            return int(
                self.caesar_adjustment.get_value()
            )
        elif self.algorithm == 'enigma':
            return (
                (
                    int(self.enigma_a.get_value()),
                    int(self.enigma_b.get_value()),
                    int(self.enigma_c.get_value())
                ),
                (
                    ROTORS[self.alphabet_combo.get_active_id()][
                        int(self.rotor_a.get_active_id())
                    ],
                    ROTORS[self.alphabet_combo.get_active_id()][
                        int(self.rotor_b.get_active_id())
                    ],
                    ROTORS[self.alphabet_combo.get_active_id()][
                        int(self.rotor_c.get_active_id())
                    ]
                )
            )
        else:
            raise ValueError('Unknown algorithm')
    
    @property
    def dec(self) -> bool:
        return self.direction_switch.get_active()

    def __init__(self, file: str, main_obj: str='main_window') -> None:
        """
        Initializes the main window of the application.

        Args:
            file (str): The path to the UI file.
            main_obj (str, optional): The ID of the main window object in the UI file. Defaults to 'main_window'.

        Returns:
            None
        """
        
        # Create the builder and load the UI file
        self.builder = Gtk.Builder()

        # Load the UI file
        self.builder.add_from_file(file)

        # Get the main window from the UI file
        self.main_window = self.builder.get_object(main_obj)

        # Load window icon from 'ui/Icon.png'
        icon = GdkPixbuf.Pixbuf.new_from_file('ui/Brutus.png')
        self.main_window.set_icon(icon)

        # Get all the objects we need
        self.get_objects()

        # Link the menus to actions
        self.link_file_actions()
        self.link_algorithm_actions()
        self.link_copy_actions()
        self.link_popover_actions()

        # Load input data
        self.update_input(enc=False)

        # Apply Caesar Cipher to data
        self.apply_algorithm('caesar', BYTE_ALPHABET, '0')

        # Update views
        self.update_text_views()

        # Link close button to quit
        self.main_window.connect('delete-event', Gtk.main_quit)

    def load_file(self, file_path: str, enc: bool=True) -> None:
        """
        Loads a file into the application.

        Args:
            file_path (str): The path to the file to load.
            enc (bool, optional): Whether the file is encrypted or not. Defaults to True.

        Returns:
            None
        """

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
        """
        Saves the data to a file.

        Args:
            file_path (str): The path to the file to save.
            enc (bool, optional): Whether the file is encrypted or not. Defaults to True.

        Returns:
            None
        """

        print(f'Saving file {file_path}...', end='', flush=True)

        if enc:
            data: bytes = self.data_enc
        else:
            data: bytes = self.data_dec

        with open(file_path, 'wb') as f:
            f.write(data)

        print(f'\t\x1B[32;1mSaved to {file_path}\x1B[0m')

    def update_view(self, enc: bool=True, hex: bool=True) -> None:
        """
        Updates the view of a single text view.

        Args:
            enc (bool, optional): Whether to update the encrypted or decrypted view. Defaults to True.
            hex (bool, optional): Whether to update the hex or text view. Defaults to True.

        Returns:
            None
        """

        if enc:
            if hex:
                self.encrypted_hex_buffer.set_text(
                    self.hex_enc
                )
            else:
                self.encrypted_text_buffer.set_text(
                    self.check_readable(self.text_enc)
                )
        else:
            if hex:
                self.decrypted_hex_buffer.set_text(
                    self.hex_dec
                )
            else:
                self.decrypted_text_buffer.set_text(
                    self.check_readable(self.text_dec)
                )

    def get_dec_buffer(self) -> str:
        """
        Returns the decrypted text buffer.

        Returns:
            str: The decrypted text buffer.
        """

        return self.decrypted_text_buffer.get_text(
            self.decrypted_text_buffer.get_start_iter(),
            self.decrypted_text_buffer.get_end_iter(),
            True
        )
    
    def set_dec_buffer(self, value: str) -> None:
        """
        Sets the decrypted text buffer.

        Args:
            value (str): The value to set the decrypted text buffer to.

        Returns:
            None
        """

        self.decrypted_text_buffer.set_text(value)

    def get_enc_buffer(self) -> str:
        """
        Returns the encrypted text buffer.

        Returns:
            str: The encrypted text buffer.
        """

        return self.encrypted_text_buffer.get_text(
            self.encrypted_text_buffer.get_start_iter(),
            self.encrypted_text_buffer.get_end_iter(),
            True
        )
    
    def set_enc_buffer(self, value: str) -> None:
        """
        Sets the encrypted text buffer.

        Args:
            value (str): The value to set the encrypted text buffer to.

        Returns:
            None
        """

        self.encrypted_text_buffer.set_text(value)

    def clean_characters(self):
        reader, setter = (
            self.get_dec_buffer, self.set_dec_buffer
        ) if not self.dec else (
            self.get_enc_buffer, self.set_enc_buffer
        )

        for char in reader():
            if char in UNREADABLE_TABLE:
                setter(reader().replace(char, UNREADABLE_TABLE[char]))
            # If char is not in readable table, replace with '?
            elif char not in string.printable:
                setter(reader().replace(char, '?'))
            else:
                pass


    def update_input(self, enc: bool=True) -> None:
        """
        Updates the input data. (pulls from the text views).

        Args:
            enc (bool, optional): Whether to update the encrypted or decrypted view. Defaults to True.

        Returns:
            None
        """

        # Reset keys generator
        self.keys = None

        if enc:
            self.text_enc = self.encrypted_text_buffer.get_text(
                self.encrypted_text_buffer.get_start_iter(),
                self.encrypted_text_buffer.get_end_iter(),
                True
            )
            self.data_enc = self.text_enc.encode()
            hex_enc = ' '.join(
                [f'{b:02X}' for b in self.data_enc]
            )
        else:
            self.text_dec = self.decrypted_text_buffer.get_text(
                self.decrypted_text_buffer.get_start_iter(),
                self.decrypted_text_buffer.get_end_iter(),
                True
            )
            self.data_dec = self.text_dec.encode()
            self.hex_dec = ' '.join(
                [f'{b:02X}' for b in self.data_dec]
            )

    def apply_algorithm(self, algorithm: str, alphabet: List[int], key: str | int) -> None:
        """
        Applies an algorithm to the active data.

        Args:
            algorithm (str): The algorithm to apply.
            alphabet (List[int]): The alphabet to use.
            key (str): The key to use.

        Returns:
            None
        """

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
            assert type(key) == str

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
        elif algorithm == 'enigma':
            if not isinstance(
                self.key, 
                Tuple):
                self.alphabet_combo.set_active(0)
                self.algorithm_combo.set_active(2)


            # Read out rotor positions
            offsets, rotors = self.key

            if self.dec:
                data = bytes(
                    b for b in
                    enigma_decrypt_sequence(
                        text=used_data,
                        rotors=rotors,
                        offsets=offsets,
                    ) # type: ignore
                )
            else:
                data = bytes(
                    b for b in
                    enigma_encrypt_sequence(
                        text=used_data,
                        rotors=rotors,
                        offsets=offsets,
                    ) # type: ignore
                )
        else:
            raise NotImplementedError

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
        """
        Callback for the open file dialog.

        Args:
            dialog (Gtk.FileChooserDialog): The dialog.
            response_id (Gtk.ResponseType): The response.

        Returns:
            None
        """

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
        """
        Callback for the save file dialog.

        Args:
            dialog (Gtk.FileChooserDialog): The dialog.
            response_id (Gtk.ResponseType): The response.

        Returns:
            None
        """

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
        """
        Links the file actions to the callbacks.

        Returns:
            None
        """

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
        Links the algorithm actions to the callbacks.

        The Algorithm should be applied upon:
            - Changing the algorithm
            - Changing the alphabet
            - Changing the key
            - Changing the text

        The algorithm should be applied based on:
            - Direction button

        Returns:
            None
        """

        # Algorithm
        self.algorithm_combo.connect('changed', self.update_algorithm)
        # Alphabet
        self.alphabet_combo.connect('changed', self.update_alphabet)
        self.custom_alphabet_entry.connect('changed', self.update_alphabet)
        # Key
        # self.key_entry.connect('changed', self.update_key)
        # Text (connect to the text view and not the buffer)
        self.decrypted_text_buffer.connect('end_user_action', self.update_text)
        self.encrypted_text_buffer.connect('end_user_action', self.update_text)
        # Direction
        self.direction_switch.connect('state-set', self.update_direction)

    def key_popover_response(self, dialog, response_id):
        """
        Callback for the key dialog.

        Args:
            dialog (Gtk.Dialog): The dialog.
            response_id (Gtk.ResponseType): The response.

        Returns:
            None
        """

        # Hide the dialog
        dialog.hide()

    def link_copy_actions(self) -> None:
        """
        Links the copy actions to the callbacks.

        Returns:
            None
        """

        # Copy
        self.copy_dec_button.connect('clicked', self.copy_dec)
        self.copy_enc_button.connect('clicked', self.copy_enc)
        self.clear_dec_button.connect('clicked', self.clear_dec)

    def copy_dec(self, button: Gtk.Button) -> None:
        """
        Callback for the copy decrypted button.

        Args:
            button (Gtk.Button): The button.

        Returns:
            None
        """

        self.copy(self.decrypted_text_buffer)

    def copy_enc(self, button: Gtk.Button) -> None:
        """
        Callback for the copy encrypted button.

        Args:
            button (Gtk.Button): The button.

        Returns:
            None
        """

        self.copy(self.encrypted_text_buffer)

    def copy(self, buffer: Gtk.TextBuffer) -> None:
        """
        Copies the text from the buffer to the clipboard.

        Args:
            buffer (Gtk.TextBuffer): The buffer.

        Returns:
            None
        """

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
        """
        Callback for the clear decrypted button.

        Args:
            button (Gtk.Button): The button.

        Returns:
            None
        """

        # Set the data to empty
        self.data_dec = b''
        self.hex_dec = ''
        self.text_dec = ''

        # Update the active text view
        self.decrypted_text_buffer.set_text('')

        # Update the other text views
        self.apply_algorithm(self.algorithm, self.alphabet, self.key)
        self.update_text_views()

    def detect_alphabet(self, button: Gtk.Button) -> None:
        """
        Callback for the detect alphabet button.

        Args:
            button (Gtk.Button): The button.

        Returns:
            None
        """

        if self.algorithm != 'caesar':
            return

        # Get the text
        text = self.text_enc if self.dec else self.text_dec

        # Detect the alphabet
        alphabet: str = caesar_guess_alphabet(text)

        # Set alphabet combo to 'Custom' (id: 5)
        self.alphabet_combo.set_active_id(alphabet)

    def detect_key(self, button: Gtk.Button) -> None:
        """
        Callback for the detect key button.

        Args:
            button (Gtk.Button): The button.

        Returns:
            None
        """


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
        self.key_buffer.set_text(str(key), -1)

        # Apply the algorithm
        self.apply_algorithm(self.algorithm, self.alphabet, str(key))

        # Update the view
        self.update_text_views()

    def update_direction(self, switch: Gtk.Switch, state: bool) -> None:
        """
        Callback for the direction switch.

        Args:
            switch (Gtk.Switch): The switch. (gets ignored)
            state (bool): The state. (gets ignored)

        Returns:
            None
        """

        self.update_text_views()
        self.keys = None

    def update_text_views(self) -> None:
        """
        Updates the text views.

        Returns:
            None
        """

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
        """
        Makes text uneditable if it is not readable.

        Returns:
            None
        """

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
        """
        Callback for the algorithm combo box.

        Args:
            combo (Gtk.ComboBox): The combo box.

        Returns:
            None
        """

        self.keys = None

        # Apply the algorithm
        self.apply_algorithm(self.algorithm, self.alphabet, self.key)

        # Update the view
        self.update_text_views()

    def update_alphabet(self, combo: Gtk.ComboBox) -> None:
        """
        Callback for the alphabet combo box.

        Args:
            combo (Gtk.ComboBox): The combo box.

        Returns:
            None
        """

        self.keys = None

        # Get the alphabet
        alphabet: List[int] = self.alphabet

        # Apply the algorithm
        self.apply_algorithm(self.algorithm, alphabet, self.key)

        # Update the view
        self.update_text_views()

    def update_key(self, entry: Gtk.Entry) -> None:
        """
        Callback for the key entry.

        Args:
            entry (Gtk.Entry): The entry.

        Returns:
            None
        """

        self.keys = None
        
        # Get the key
        key: str = entry.get_text()

        # Apply the algorithm
        self.apply_algorithm(self.algorithm, self.alphabet, key)

        # Update the view
        self.update_text_views()

    def update_text(self, buffer: Gtk.TextBuffer) -> None:
        """
        Callback for the text buffer.

        Args:
            buffer (Gtk.TextBuffer): The text buffer.

        Returns:
            None
        """

        self.keys = None

        self.clean_characters()

        # Update input
        self.update_input(self.dec)

        # Apply the algorithm
        self.apply_algorithm(self.algorithm, self.alphabet, self.key)

        # Update the view
        self.update_text_views()

    def check_readable(self, text: str) -> str:
        """
        Checks if the text is readable.

        Args:
            text (str): The text.

        Returns:
            str: The text if it is readable, otherwise an error message.
        """

        # Check if there are non-readable characters
        if any(
            c not in string.printable or c in UNREADABLE_TABLE
            for c in text
        ):
            return 'Non-readable characters\nLook at the hex view'
        
        # Return the text
        return text

    def get_objects(self) -> None:
        """
        Gets the objects from the ui (glade) file.

        Returns:
            None
        """

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
        self.key_buffer = self.builder.get_object('key_buffer')
        ### Set Key button
        self.key_popover_button = self.builder.get_object('key_popover_button')
        ### Key dialog
        self.key_popover = self.builder.get_object('key_popover')
        ### Detect Buttons (key and alphabet)
        # self.key_detect_button = self.builder.get_object('key_detect_button')
        # self.alphabet_detect_button = self.builder.get_object('alphabet_detect_button')
        ### Direction Switch
        self.direction_switch = self.builder.get_object('direction_switch')
        ### Custom alphabet entry
        self.custom_alphabet_entry = self.builder.get_object('custom_alphabet_entry')
        ### Break dialog button
        self.break_popover_button = self.builder.get_object('break_popover_button')
        self.break_popover = self.builder.get_object('break_popover')
        self.break_combo = self.builder.get_object('break_combo')
        self.break_entry = self.builder.get_object('break_entry')

        assert None not in [
            self.algorithm_combo,
            self.algorithm_entry,
            self.alphabet_combo,
            self.alphabet_entry,
            self.key_buffer,
            self.key_popover_button,
            self.key_popover,
            self.direction_switch,
            self.break_popover_button,
            self.custom_alphabet_entry,
            self.break_popover,
            self.break_combo,
            self.break_entry
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

        # Adjustments
        self.caesar_adjustment = self.builder.get_object('caesar_adjustment')
        self.enigma_a = self.builder.get_object('enigma_a') # GtkSpinButton
        self.enigma_b = self.builder.get_object('enigma_b')
        self.enigma_c = self.builder.get_object('enigma_c')
        self.rotor_a = self.builder.get_object('rotor_a') # GtkComboBoxText
        self.rotor_b = self.builder.get_object('rotor_b')
        self.rotor_c = self.builder.get_object('rotor_c')

        # Key input
        self.vigenere_key_entry = self.builder.get_object('vigenere_key_entry')

        # Key stack
        self.key_stack = self.builder.get_object('key_stack')

        # Panes
        self.caesar_key_pane = self.builder.get_object('caesar_key_pane')
        self.enigma_key_pane = self.builder.get_object('enigma_key_pane')
        self.vigenere_key_pane = self.builder.get_object('vigenere_key_pane')

        assert None not in [
            self.caesar_adjustment,
            self.enigma_a,
            self.enigma_b,
            self.enigma_c,
            self.rotor_a,
            self.rotor_b,
            self.rotor_c,
            self.vigenere_key_entry,
            self.key_stack,
            self.caesar_key_pane,
            self.enigma_key_pane,
            self.vigenere_key_pane
        ], 'Failed to get the adjustments'

        # Alphabet popover
        self.alphabet_popover = self.builder.get_object('alphabet_popover')
        ## Button
        self.alphabet_popover_button = self.builder.get_object('alphabet_popover_button')

        assert None not in [
            self.alphabet_popover,
            self.alphabet_popover_button
        ], 'Failed to get the alphabet popover'

    def link_popover_actions(self) -> None:
        # Clicking the popover button opens the popover
        self.key_popover_button.connect('clicked', self.key_popover_button_clicked)

        # Internal updates
        ## Key buffer (EntryBuffer)
        self.key_buffer.connect('deleted-text', self.key_buffer_changed)
        self.key_buffer.connect('inserted-text', self.key_buffer_changed)

        ## Spin buttons
        self.caesar_adjustment.connect('value-changed', self.caesar_adjustment_changed)
        self.enigma_a.connect('value-changed', lambda _: self.enigma_adjustment_changed(0))
        self.enigma_b.connect('value-changed', lambda _: self.enigma_adjustment_changed(1))
        self.enigma_c.connect('value-changed', lambda _: self.enigma_adjustment_changed(2))
        self.rotor_a.connect('changed', lambda _: self.enigma_adjustment_changed(0))
        self.rotor_b.connect('changed', lambda _: self.enigma_adjustment_changed(1))
        self.rotor_c.connect('changed', lambda _: self.enigma_adjustment_changed(2))

        # Alphabet popover
        self.alphabet_popover_button.connect('clicked', self.alphabet_popover_button_clicked)

        # Break dialog
        self.break_popover_button.connect('clicked', self.break_popover_button_clicked)

        # Break combo set -> set the key
        self.break_combo.connect('changed', self.break_combo_changed)

    def break_combo_changed(self, combo: Gtk.ComboBoxText) -> None:
        """
        Callback for the break combo.

        Args:
            combo: The combo.

        Returns:
            None
        """

        # Set the key
        if self.algorithm == 'caesar':
            self.caesar_adjustment.set_value(int(combo.get_active_text()))

    def break_popover_button_clicked(self, *_) -> None:
        """
        Callback for the break popover button.

        Args:
            _: The button.

        Returns:
            None
        """


        if not self.dec:
            # Clear options
            self.break_combo.remove_all()
        else:
            if self.algorithm == 'caesar':
                keys = list(caesar_guess_shift(
                    self.text_enc,
                    'en',
                    alphabet=''.join(chr(c) for c in self.alphabet),
                    max_shift=len(self.alphabet)
                ))

                # Clear options
                self.break_combo.remove_all()

                # Add options
                for key in keys[:5]:
                    self.break_combo.append_text(str(key))

                # Set active
                self.break_combo.set_active(0)
            # elif self.algorithm == 'vigenere':
            #     key = vigenere_break_vari(
            #         self.text_enc,
            #         ''.join(chr(c) for c in self.alphabet)
            #     )
            #
            #     # Set the key
            #     self.vigenere_key_entry.set_text(key)
            # 
            #     # Clear options
            #     self.break_combo.remove_all()
            # 
            #     # Add options
            #     self.break_combo.append_text(key)

        # Show the popover
        self.break_popover.show_all()

    def alphabet_popover_button_clicked(self, *_) -> None:
        """
        Callback for the alphabet popover button.

        Args:
            _: The button.

        Returns:
            None
        """

        # Show the popover
        self.alphabet_popover.show_all()

        # Set active alphabet to custom
        self.alphabet_combo.set_active(6)

    def key_buffer_changed(self, *_) -> None:
        """
        Callback for the key buffer.

        Args:
            buffer (Gtk.TextBuffer): The buffer.

        Returns:
            None
        """

        # Apply algorithm
        self.apply_algorithm(
            self.algorithm,
            self.alphabet,
            self.key
        )

        # Update view
        self.update_text_views()

    def caesar_adjustment_changed(self, adjustment: Gtk.Adjustment) -> None:
        """
        Callback for the Caesar adjustment.

        Args:
            adjustment (Gtk.Adjustment): The adjustment.

        Returns:
            None
        """

        # Set max value according to the alphabet
        adjustment.set_upper(len(self.alphabet) - 1)

        # Adjust the value if it's out of bounds
        if adjustment.get_value() > adjustment.get_upper():
            adjustment.set_value(adjustment.get_upper())

        # Apply algorithm
        self.apply_algorithm(
            self.algorithm,
            self.alphabet,
            self.key
        )

        # Update view
        self.update_text_views()

    def enigma_adjustment_changed(self, rotor: int) -> None:
        """
        Callback for the Enigma adjustment.

        Args:
            rotor (int): The rotor.

        Returns:
            None
        """

        # Set max value according to the alphabet
        for adjustment in [self.enigma_a, self.enigma_b, self.enigma_c]:
            adjustment.set_upper(len(self.alphabet) - 1)

            # Adjust the value if it's out of bounds
            if adjustment.get_value() > adjustment.get_upper():
                adjustment.set_value(adjustment.get_upper())

        # Apply algorithm
        self.apply_algorithm(
            self.algorithm,
            self.alphabet,
            self.key
        )

        # Update view
        self.update_text_views()

    def key_popover_button_clicked(self, button):
        """
        Callback for the key popover button.

        Args:
            button (Gtk.Button): The button.

        Returns:
            None
        """

        # Choose the correct popover stack pane
        if self.algorithm == 'caesar':
            self.key_stack.set_visible_child(self.caesar_key_pane)
        elif self.algorithm == 'enigma':
            self.key_stack.set_visible_child(self.enigma_key_pane)
        elif self.algorithm == 'vigenere':
            self.key_stack.set_visible_child(self.vigenere_key_pane)
        else:
            raise ValueError('Unknown algorithm')

        # Show the popover
        self.key_popover.show_all()

    def show(self) -> None:
        self.main_window.show_all()

def main() -> None:
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

if __name__ == '__main__':
    main()