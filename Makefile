# Makefile
# ------

# Target binary
TARGET = Brutus
SHELL = /bin/bash
PYINSTALLER = ./.venv/bin/pyinstaller

# Make rule
all:
	source .venv/bin/activate
	$(PYINSTALLER) build.spec
	cp ui/$(TARGET).* dist/

# Install rule
install:
	# Binary
	cp dist/$(TARGET) /usr/local/bin/$(TARGET)
	# Desktop entry
	cp dist/$(TARGET).desktop /usr/share/applications/$(TARGET).desktop
	# Icon
	cp dist/$(TARGET).png /usr/share/pixmaps/$(TARGET).png

# Uninstall rule
uninstall:
	# Binary
	rm -f /usr/local/bin/$(TARGET)
	# Desktop entry
	rm -f /usr/share/applications/$(TARGET).desktop
	# Icon
	rm -f /usr/share/pixmaps/$(TARGET).png

# Alias rule for uninstall
remove: uninstall

# Clean rule
clean:
	rm -rf build dist