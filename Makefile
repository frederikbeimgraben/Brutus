# Makefile
# ------

# Target binary
TARGET = Brutus
SHELL = /bin/bash
PYINSTALLER = pyinstaller

# Make rule
all:
	rm -rf build dist
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