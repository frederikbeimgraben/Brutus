"""
Graphical User Interface for the application using gi.repository: Gtk+

Use the `ui/main_window.ui` as the UI source file.
"""

# Standard library imports
import os
import sys

# Third party imports
import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, Gio, Gdk, GLib

# Local imports
from encrypt import caesar_encrypt_sequence, caesar_decrypt_sequence
from encrypt import vigenere_encrypt_sequence, vigenere_decrypt_sequence
from break_lib import caesar_break, caesar_guess_alphabet, caesar_guess_shift
from encrypt_file import apply_file

# Constants
BYTE_ALPHABET = [
    n for n in range(256)
]

# GUI
## Main window
builder = Gtk.Builder()
builder.add_from_file('ui/main_window.ui')

# Load class `main_window` from the UI file
main_window = builder.get_object('main_window')

# Show the main window
main_window.show_all()

# Wait for the window to close
Gtk.main()

