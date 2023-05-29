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
from encrypt import vigenere_encrypt_sequence, vigenere_decrypt_sequence
from encrypt import enigma_decrypt_sequence, enigma_encrypt_sequence, EnigmaRotor
from break_lib import caesar_guess_shift

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
            alphabet=alphabet, # type: ignore
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

OBJECTS: Dict[str, Dict] = {
    'Text Views' : {
        'Decrypted' : {
            'decrypted_text_view' : ('GtkTextView', 'text_dec_box'),
            'decrypted_text_buffer' : ('GtkTextBuffer', 'text_dec')
        },
        'Encrypted' : {
            'encrypted_text_view' : ('GtkTextView', 'text_enc_box'),
            'encrypted_text_buffer' : ('GtkTextBuffer', 'text_enc')
        }
    },
    'Hex Views' : {
        'Decrypted' : {
            'decrypted_hex_view' : ('GtkTextView', 'hex_dec_box'),
            'decrypted_hex_buffer' : ('GtkTextBuffer', 'hex_dec')
        },
        'Encrypted' : {
            'encrypted_hex_view' : ('GtkTextView', 'hex_enc_box'),
            'encrypted_hex_buffer' : ('GtkTextBuffer', 'hex_enc')
        }
    },
    'Controls' : {
        'Direction' : {
            'direction_switch' : ('GtkSwitch', 'direction_switch')
        },
        'Algorithm' : {
            'algorithm_combo' : ('GtkComboBoxText', 'algorithm_combo'),
            'algorithm_entry' : ('GtkEntry', 'algorithm_entry')
        },
        'Alphabet' : {
            'alphabet_combo' : ('GtkComboBoxText', 'alphabet_combo'),
            'alphabet_entry' : ('GtkEntry', 'alphabet_entry')
        },
        'Custom Alphabet' : {
            'alphabet_popover' : ('GtkPopover', 'alphabet_popover'),
            'alphabet_popover_button' : ('GtkButton', 'alphabet_popover_button'),
            'custom_alphabet_entry' : ('GtkEntry', 'custom_alphabet_entry'),
        },
        'Key' : {
            'PopOver': {
                'key_popover' : ('GtkPopover', 'key_popover'),
                'key_popover_button' : ('GtkButton', 'key_popover_button'),
                'Algorithms' : {
                    'Caesar' : {
                        # Pane
                        'caesar_key_pane' : ('GtkGrid', 'caesar_key_pane'),
                        # Spin button
                        'caesar_input' : ('GtkSpinButton', 'caesar_input'),
                        'caesar_adjustment' : ('GtkAdjustment', 'caesar_adjustment'),
                    },
                    'Vigenere' : {
                        # Pane
                        'vigenere_key_pane' : ('GtkGrid', 'vigenere_key_pane'),
                        # Entry
                        'vigenere_key_entry' : ('GtkEntry', 'vigenere_key_entry'),
                        # Buffer
                        'key_buffer' : ('GtkTextBuffer', 'key_buffer'),
                    },
                    'Enigma' : {
                        # Pane
                        'enigma_key_pane' : ('GtkGrid', 'enigma_key_pane'),
                        # Rotors
                        'rotor_a' : ('GtkEntry', 'rotor_a'),
                        'rotor_b' : ('GtkEntry', 'rotor_b'),
                        'rotor_c' : ('GtkEntry', 'rotor_c'),
                        # Ring settings
                        'enigma_a' : ('GtkSpinButton', 'enigma_a'),
                        'enigma_b' : ('GtkSpinButton', 'enigma_b'),
                        'enigma_c' : ('GtkSpinButton', 'enigma_c'),
                        # TODO: Plugboard
                    }
                },
                'key_stack' : ('GtkStack', 'key_stack'),
            }
        },
        'Break' : {
            # Popover
            'PopOver' : {
                'break_popover' : ('GtkPopover', 'break_popover'),
                'break_popover_button' : ('GtkButton', 'break_popover_button'),
                # Combo
                'break_combo' : ('GtkComboBoxText', 'break_combo'),
                # Entry
                'break_entry' : ('GtkEntry', 'break_entry'),
            }
        }
    },
    'File Save/Load' : {
        'Save' : {
            'save_file_button' : ('GtkButton', 'save_file_button'),
            'save_file_dialog' : ('GtkFileChooserDialog', 'save_file_dialog'),
            'save_is_encrypted_combo' : ('GtkComboBoxText', 'save_is_encrypted_combo'),
            'save_is_encrypted_entry' : ('GtkEntry', 'save_is_encrypted_entry'),
            'file_name_entry' : ('GtkEntry', 'file_name_entry'),
            'save_ok_button' : ('GtkButton', 'save_ok_button'),
            'save_close_button' : ('GtkButton', 'save_close_button'),
        },
        'Open' : {
            'open_file_button' : ('GtkButton', 'open_file_button'),
            'open_file_dialog' : ('GtkFileChooserDialog', 'open_file_dialog'),
            'open_is_encrypted_combo' : ('GtkComboBoxText', 'open_is_encrypted_combo'),
            'open_is_encrypted_entry' : ('GtkEntry', 'open_is_encrypted_entry'),
            'open_ok_button' : ('GtkButton', 'open_ok_button'),
            'open_close_button' : ('GtkButton', 'open_close_button'),
        }
    },
    'Misc' : {
        'Clipboard' : {
            'copy_dec_button' : ('GtkButton', 'copy_dec_button'),
            'copy_enc_button' : ('GtkButton', 'copy_enc_button'),
        },
        'Reset' : {
            'clear_dec_button' : ('GtkButton', 'clear_dec_button'),
        },
    }
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

    # Annotations
    decrypted_text_view: Gtk.TextView
    decrypted_text_buffer: Gtk.TextBuffer
    encrypted_text_view: Gtk.TextView
    encrypted_text_buffer: Gtk.TextBuffer
    decrypted_hex_view: Gtk.TextView
    decrypted_hex_buffer: Gtk.TextBuffer
    encrypted_hex_view: Gtk.TextView
    encrypted_hex_buffer: Gtk.TextBuffer
    direction_switch: Gtk.Switch
    algorithm_combo: Gtk.ComboBoxText
    algorithm_entry: Gtk.Entry
    alphabet_combo: Gtk.ComboBoxText
    alphabet_entry: Gtk.Entry
    alphabet_popover: Gtk.Popover
    alphabet_popover_button: Gtk.Button
    custom_alphabet_entry: Gtk.Entry
    key_popover: Gtk.Popover
    key_popover_button: Gtk.Button
    caesar_key_pane: Gtk.Grid
    caesar_input: Gtk.SpinButton
    caesar_adjustment: Gtk.Adjustment
    vigenere_key_pane: Gtk.Grid
    vigenere_key_entry: Gtk.Entry
    key_buffer: Gtk.TextBuffer
    enigma_key_pane: Gtk.Grid
    rotor_a: Gtk.Entry
    rotor_b: Gtk.Entry
    rotor_c: Gtk.Entry
    enigma_a: Gtk.SpinButton
    enigma_b: Gtk.SpinButton
    enigma_c: Gtk.SpinButton
    key_stack: Gtk.Stack
    break_popover: Gtk.Popover
    break_popover_button: Gtk.Button
    break_combo: Gtk.ComboBoxText
    break_entry: Gtk.Entry
    save_file_button: Gtk.Button
    save_file_dialog: Gtk.FileChooserDialog
    save_is_encrypted_combo: Gtk.ComboBoxText
    save_is_encrypted_entry: Gtk.Entry
    file_name_entry: Gtk.Entry
    save_ok_button: Gtk.Button
    save_close_button: Gtk.Button
    open_file_button: Gtk.Button
    open_file_dialog: Gtk.FileChooserDialog
    open_is_encrypted_combo: Gtk.ComboBoxText
    open_is_encrypted_entry: Gtk.Entry
    open_ok_button: Gtk.Button
    open_close_button: Gtk.Button
    copy_dec_button: Gtk.Button
    copy_enc_button: Gtk.Button
    clear_dec_button: Gtk.Button

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
            return [
                ord(c) 
                for c in 
                self.custom_alphabet_entry.get_text()
            ]
        else:
            return alphabet.copy()
    
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

        # Load input data
        self.update_input(enc=False)

        # Link all the actions
        self.link_all()

        # Apply Caesar Cipher to data
        self.update_view()

        # Link close button to quit
        self.main_window.connect('delete-event', Gtk.main_quit)

    def get_objects(
            self,
            objects: Dict | Tuple=OBJECTS,
            path: List[str] | None=None,
            registered: List[Tuple] | None=None) -> List[Tuple]:
        """
        Gets the objects from the ui (glade) file.

        Returns:
            None
        """

        if path is None:
            path = []

        if registered is None:
            registered = []
        
        builder = self.builder

        ind = '\x1B[35m|\t' * (len(path) - 1)

        if not isinstance(objects, dict):
            print(
                f'\x1B[37m[L] {ind}\x1B[35;1m{path[-1]}\x1B[0m : \x1B[34;1m{objects[0]}\x1B[0m'
            )
            # Assign property to self
            setattr(self, path[-1], builder.get_object(objects[1]))
            # Check if attribute is None
            if getattr(self, path[-1]) is None:
                raise AttributeError(f'Could not get object {path[-1]} ({objects[1]}))')

            registered.append(
                (path[-1], objects[0],)
            )

            return registered
        else:
            if len(path) > 0:
                print(
                    f'\x1B[37m[E] {ind}\x1B[35;1m{path[-1]}\x1B[0m'
                )

            # Get the objects
            for key, value in objects.items():
                self.get_objects(value, path + [key], registered)

            return registered

    # Linking
    def link_all(self) -> None:
        """
        Links all the actions to their respective functions.

        Returns:
            None
        """

        self.link_file_actions()
        self.link_misc()
        self.link_control_actions()
    
    def link_control_actions(self) -> None:
        # Clicking the popover button opens the popover
        self.key_popover_button.connect('clicked', self.key_popover_button_clicked)

        # Vigenere key buffer
        self.key_buffer.connect('deleted-text', self.key_buffer_changed)
        self.key_buffer.connect('inserted-text', self.key_buffer_changed)

        # Spin buttons
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

        # Algorithm
        self.algorithm_combo.connect('changed', self.update_algorithm)

        # Alphabet
        self.alphabet_combo.connect('changed', self.update_alphabet)
        self.custom_alphabet_entry.connect('changed', self.update_alphabet)

        # Update text
        self.decrypted_text_buffer.connect('end_user_action', self.update_text)
        self.encrypted_text_buffer.connect('end_user_action', self.update_text)

        # Direction
        self.direction_switch.connect('state-set', self.update_direction)   

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

    def link_misc(self) -> None:
        """
        Links the copy actions to the callbacks.

        Returns:
            None
        """

        # Copy
        self.copy_dec_button.connect('clicked', self.copy_dec)
        self.copy_enc_button.connect('clicked', self.copy_enc)
        self.clear_dec_button.connect('clicked', self.clear_dec)

    # Updaters
    def update_view(self) -> None:
        """
        Updates all the views.

        Returns:
            None
        """

        # Apply algorithm
        self.apply_algorithm(self.algorithm, self.alphabet, self.key) # type: ignore

        # Update text views
        self.update_text_views()

    def update_all_views(self) -> None:
        """
        Updates all the views.

        Returns:
            None
        """

        # Apply algorithm
        self.apply_algorithm(self.algorithm, self.alphabet, self.key) # type: ignore

        [
            self.update_text_view(enc, hex)
            for enc in [True, False]
            for hex in [True, False]
        ]

    def update_text_view(self, enc: bool=True, hex: bool=True) -> None:
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
            self.text_enc = self.get_enc_buffer()
            self.data_enc = self.text_enc.encode()
            hex_enc = ' '.join(
                [f'{b:02X}' for b in self.data_enc]
            )
        else:
            self.text_dec = self.get_dec_buffer()
            self.data_dec = self.text_dec.encode()
            self.hex_dec = ' '.join(
                [f'{b:02X}' for b in self.data_dec]
            )

    # File actions
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

            # Update the views
            self.update_all_views()

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

    # Buffer getters and setters
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

    # Algorithm actions
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

    def apply_algorithm(
            self, 
            algorithm: str, 
            alphabet: List[int], 
            key: str | int | Tuple[Tuple[int, ...], Tuple[EnigmaRotor, ...]]) -> None:
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
            assert type(key) == str or type(key) == int

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
            assert type(key) == tuple

            # Read out rotor positions
            offsets, rotors = key

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

    # Response callbacks
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
        self.update_view()

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

        self.update_text_view(not self.dec, False)
        self.update_text_view(not self.dec, True)
        self.update_text_view(self.dec, True)

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

        self.update_view()

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

        self.update_view()

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

        self.update_view()

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

        self.update_view()
    
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

        self.update_view()

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

        self.update_view()

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

        self.update_view()

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
        
    # Clipboard
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