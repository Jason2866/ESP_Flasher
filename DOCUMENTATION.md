# ESP-Flasher Documentation

**Version:** 4.0.0  
**License:** MIT  
**Author:** Jason2866 (Johann Obermeier)  
**Repository:** [github.com/Jason2866/ESP_Flasher](https://github.com/Jason2866/ESP_Flasher)

---

## Table of Contents

- [Overview](#overview)
- [Supported Chips](#supported-chips)
- [Features](#features)
- [Installation](#installation)
  - [Pre-built Binaries](#pre-built-binaries)
  - [From PyPI](#from-pypi)
  - [From Source](#from-source)
  - [Linux Permissions](#linux-permissions)
- [Usage](#usage)
  - [GUI Mode](#gui-mode)
  - [Command Line Interface](#command-line-interface)
  - [CLI Arguments](#cli-arguments)
- [Architecture](#architecture)
  - [Project Structure](#project-structure)
  - [Module Overview](#module-overview)
  - [Flashing Process](#flashing-process)
  - [Firmware Detection](#firmware-detection)
  - [Bootloader & Partition Handling](#bootloader--partition-handling)
  - [ANSI Color Support](#ansi-color-support)
- [Supported Flash Configurations](#supported-flash-configurations)
  - [Flash Sizes](#flash-sizes)
  - [Flash Modes](#flash-modes)
  - [Flash Frequencies](#flash-frequencies)
  - [Bootloader Offsets per Chip](#bootloader-offsets-per-chip)
  - [Memory Layout (per Chip)](#memory-layout-per-chip)
- [Building Standalone Binaries](#building-standalone-binaries)
  - [macOS](#macos)
  - [macOS (ARM)](#macos-arm)
  - [Windows](#windows)
  - [Linux (Ubuntu)](#linux-ubuntu)
- [CI/CD](#cicd)
  - [Build Pipeline](#build-pipeline)
  - [PyPI Publishing](#pypi-publishing)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Overview

ESP-Flasher (Tasmota-ESP-Flasher) is a cross-platform flashing tool designed specifically for flashing [Tasmota](https://tasmota.github.io/) firmware onto ESP8266 and ESP32-family microcontrollers. It provides both a graphical user interface (PyQt5) and a command line interface.

The tool wraps [esptool](https://github.com/espressif/esptool) functionality in a custom module (`own_esptool.py`) and automates the entire flashing workflow, including bootloader selection, partition table handling, safeboot image management, and ELF-to-binary conversion.

---

## Supported Chips

| Chip | ROM Loader Class | Image Chip ID |
|------|-----------------|---------------|
| ESP8266 | `ESP8266ROM` | 0 |
| ESP32 | `ESP32ROM` | 0 |
| ESP32-S2 | `ESP32S2ROM` | 2 |
| ESP32-S3 | `ESP32S3ROM` | 9 |
| ESP32-C2 | `ESP32C2ROM` | 12 |
| ESP32-C3 | `ESP32C3ROM` | 5 |
| ESP32-C5 | `ESP32C5ROM` | — |
| ESP32-C6 | `ESP32C6ROM` | 13 |
| ESP32-C61 | `ESP32C61ROM` | — |
| ESP32-H2 | `ESP32H2ROM` | 16 |
| ESP32-P4 | `ESP32P4ROM` | — |

---

## Features

- **Auto-detection** of connected ESP chip type and revision
- **Automatic bootloader selection** based on chip model, flash mode, and flash frequency
- **Factory image support** — detects and flashes Tasmota factory images directly
- **Safeboot partition scheme** — automatically downloads and includes safeboot firmware for ESP32-family chips
- **ELF-to-binary conversion** of bootloader files
- **Configurable baud rate** (default: 1,500,000 for ESP32, falls back to 115,200 if unsupported)
- **Flash erase** before writing (can be disabled with `--no-erase`)
- **Interactive serial monitor** with command input support, ANSI colors, and timestamps
- **ANSI color support** — full support for colored and formatted terminal output (bold, italic, underline, colors)
- **Dynamic console interface** — input field appears when viewing logs for sending commands
- **Dark-themed GUI** built with PyQt5 using the Fusion style
- **Cross-platform** — Windows, macOS (Intel + ARM), and Linux (X11 + Wayland)

---

## Installation

### Pre-built Binaries

Download the latest release for your operating system from the [Releases page](https://github.com/Jason2866/ESP_Flasher/releases/latest). Simply download, extract (if necessary), and run.

| Platform | Binary |
|----------|--------|
| Windows | `ESP-Flasher.exe` |
| macOS (Intel) | `ESP-Flasher-macOS.app` (tar archive) |
| macOS (ARM/Apple Silicon) | `ESP-Flasher-macOSarm.app` (tar archive) |
| Linux (Ubuntu) | `ESP-Flasher` (tar archive) |

### From PyPI

```bash
pip install esp-flasher
```

Launch the GUI:
```bash
esp_flasher
```

### From Source

```bash
git clone https://github.com/Jason2866/ESP_Flasher.git
cd ESP_Flasher
pip install -e .
```

Launch the GUI:
```bash
esp_flasher
```

Or use the CLI:
```bash
esp_flasher -h
```

**Requirements** (Python ≥ 3.8, < 4.0):
- `pyserial >= 3.5`
- `requests >= 2.24.0, < 3`
- `PyQt5 >= 5.15.10`
- `distro >= 1.9.0`

### Linux Permissions

On Linux, add your user to the `dialout` group to access serial ports:

```bash
sudo usermod -a -G dialout $(whoami)
```

Log out and log back in for the change to take effect.

---

## Usage

### GUI Mode

Run `esp_flasher` without any arguments to launch the graphical interface:

```bash
esp_flasher
```

The GUI provides:
1. **Serial Port** — a dropdown to select the target port
   - **Connect Button** — Click to connect/disconnect from the selected port
   - Automatically reloads available ports when clicked
   - Button turns green when connected, shows "Disconnect"
   - Button is gray when disconnected, shows "Connect"
2. **Firmware** — a file browser to select a `.bin` firmware file (optional, only for flashing)
3. **Flash ESP** — starts the flashing process (disconnects during flash, reconnects after if was connected)
4. **Console** — displays real-time serial output
   - Input field at the bottom for sending commands (enabled when connected)
   - ANSI color support for colored output
   - Timestamps for serial log lines
   - Clear button to reset console

### Command Line Interface

```bash
esp_flasher [OPTIONS] BINARY
```

**Example:**
```bash
esp_flasher --port /dev/ttyUSB0 tasmota.bin
```

### CLI Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `BINARY` | Path to the firmware binary file (required) | — |
| `-p`, `--port` | Serial port to use | Auto-detect |
| `--esp8266` | Force ESP8266 chip type | Auto-detect |
| `--esp32` | Force ESP32 chip type | Auto-detect |
| `--esp32s2` | Force ESP32-S2 chip type | Auto-detect |
| `--esp32s3` | Force ESP32-S3 chip type | Auto-detect |
| `--esp32c2` | Force ESP32-C2 chip type | Auto-detect |
| `--esp32c3` | Force ESP32-C3 chip type | Auto-detect |
| `--esp32c5` | Force ESP32-C5 chip type | Auto-detect |
| `--esp32c6` | Force ESP32-C6 chip type | Auto-detect |
| `--esp32c61` | Force ESP32-C61 chip type | Auto-detect |
| `--esp32p4` | Force ESP32-P4 chip type | Auto-detect |
| `--upload-baud-rate` | Baud rate for uploading | `1500000` |
| `--bootloader` | Custom bootloader ELF path/URL (ESP32x only) | Auto-download |
| `--safeboot` | Custom safeboot factory image path/URL (ESP32x only) | Auto-download |
| `--partitions` | Custom partition table path/URL (ESP32x only) | Auto-download |
| `--otadata` | Custom OTA data file path/URL (ESP32x only) | Auto-download |
| `--input` | Custom bootloader ELF file to flash (ESP32x only) | — |
| `--no-erase` | Do not erase flash before flashing | `false` |
| `--show-logs` | Only show serial logs (no flashing) | `false` |

---

## Architecture

### Project Structure

```
ESP_Flasher/
├── esp_flasher/                  # Main Python package
│   ├── __init__.py
│   ├── __main__.py               # Entry point (CLI + GUI launcher)
│   ├── common.py                 # Chip info classes, flash configuration logic
│   ├── const.py                  # Constants, version, URLs
│   ├── console_color.py          # ANSI color support for terminal output
│   ├── gui.py                    # PyQt5 GUI implementation
│   ├── helpers.py                # Utility functions
│   ├── serial_console.py         # Interactive serial console with input support
│   └── own_esptool.py            # Custom esptool (ESP ROM loaders, flash operations)
├── bootloader/                   # Pre-built bootloader ELF files per chip
│   ├── esp32/
│   ├── esp32c2/
│   ├── esp32c3/
│   ├── esp32c5/
│   ├── esp32c6/
│   ├── esp32c61/
│   ├── esp32h2/
│   ├── esp32p4/
│   ├── esp32p4rev3/
│   ├── esp32s2/
│   └── esp32s3/
├── partitions/                   # Partition table binaries per chip
│   ├── boot_app0.bin
│   ├── partitions.esp32.bin
│   ├── partitions.esp32c2.bin
│   ├── partitions.esp32c3.bin
│   ├── partitions.esp32c5.bin
│   ├── partitions.esp32c6.bin
│   ├── partitions.esp32c61.bin
│   ├── partitions.esp32p4.bin
│   ├── partitions.esp32p4rev3.bin
│   ├── partitions.esp32s2.bin
│   └── partitions.esp32s3.bin
├── examples/                     # Example scripts
│   ├── colored_output_example.py # ANSI color usage example
│   └── serial_console_example.py # Serial console with input example
├── .github/workflows/            # CI/CD workflows
│   ├── build.yml                 # Build binaries for all platforms
│   └── build_pypi.yml            # Publish to PyPI
├── setup.py                      # Package setup
├── requirements.txt              # Runtime dependencies
├── requirements_build.txt        # Build dependencies (PyInstaller)
├── ESP-Flasher.spec              # PyInstaller spec file
├── icon.icns                     # macOS app icon
├── icon.ico                      # Windows app icon
├── ANSI_COLOR_SUPPORT.md         # ANSI color support documentation
├── test_ansi_colors.py           # Test script for ANSI colors
└── README.md
```

### Module Overview

#### `__main__.py`
The application entry point. If no command line arguments are provided, it launches the PyQt5 GUI. Otherwise, it runs the CLI flashing workflow:
1. Parse arguments
2. Select / auto-detect serial port
3. Detect chip type and read chip info
4. Run the stub loader
5. Negotiate baud rate
6. Detect flash size
7. Configure flash arguments (bootloader, partitions, safeboot, firmware)
8. Convert ELF bootloader to binary (if needed)
9. Erase flash (unless `--no-erase`)
10. Write flash
11. Hard reset and show serial logs

#### `common.py`
Contains the core flashing logic:
- **`ChipInfo`** / **`ESP32ChipInfo`** / **`ESP8266ChipInfo`** — Data classes holding chip metadata (model, MAC, features)
- **`read_chip_info()`** — Reads chip description and features using MCU-specific ROM methods
- **`detect_chip()`** — Connects to a chip on a serial port (auto-detect or forced type)
- **`configure_write_flash_args()`** — Builds the complete flash argument set:
  - Determines chip model and selects matching bootloader, partitions, and safeboot image
  - Downloads remote files as needed (bootloaders, partitions, safeboot images)
  - Caches bootloader ELF files locally in `~/ESP_Flasher_<version>/`
- **`read_firmware_info()`** — Parses firmware binary headers to extract flash mode, frequency, and detect factory images
- **`open_downloadable_binary()`** — Opens firmware from local path, HTTP URL, or file-like object

#### `own_esptool.py`
A self-contained, customized version of Espressif's esptool (based on v3.6.0). It contains:
- **`ESPLoader`** — Base class for all ESP ROM/stub communication
- Chip-specific ROM loader classes for each supported chip family
- Stub loader classes for each chip
- Flash read/write/erase operations
- ELF-to-binary image conversion (`elf2image()`)
- Serial port detection (`get_port_list()`)

#### `gui.py`
PyQt5-based GUI with:
- Dark Fusion theme
- Serial port selection with single Connect button
  - Connect button reloads ports and connects in one action
  - Button changes color: green when connected, gray when disconnected
  - Button text changes: "Disconnect" when connected, "Connect" when disconnected
- Firmware file browser (`.bin` filter)
- Flash button that disconnects during flashing and reconnects after (if was connected)
- Console with always-visible input field:
  - Shows serial output in real-time
  - Input field enabled when serial connection is active
  - ANSI color support via `ColoredConsole`
  - Automatic timestamping for serial logs
- `FlashingThread` — runs flashing in a background daemon thread
- Automatic Qt platform detection (Cocoa/XCB/Wayland/Windows)

#### `serial_console.py`
Serial port reader for log viewing:
- **`SerialReader`** — Thread-safe serial port reader that runs in background
- Emits Qt signals for received lines and errors
- Automatic timestamping of received lines
- Proper cleanup on stop

#### `console_color.py`
ANSI color code parser and renderer:
- **`ConsoleState`** — Tracks current text formatting state (bold, italic, colors, etc.)
- **`ColoredConsole`** — Main class that processes ANSI escape sequences and applies formatting using Qt's `QTextCharFormat`
- Supports SGR (Select Graphic Rendition) codes 0-49
- Handles carriage returns for progress indicators
- Thread-safe via Qt signals

#### `const.py`
Application constants:
- `__version__` — Current version string
- Remote URLs for bootloader ELFs, partition tables, OTA data, and safeboot images
- `HTTP_REGEX` — Pattern for validating HTTP(S) URLs

#### `helpers.py`
Utility function `prevent_print()` — temporarily suppresses stdout during esptool calls to hide internal debug output.

### Flashing Process

The following describes the complete flashing workflow for an ESP32-family chip with a non-factory firmware image:

1. **Chip Detection** — The chip is detected via its magic value (`CHIP_DETECT_MAGIC_VALUE`) or forced via CLI flag
2. **Connection** — The tool connects using `no_reset` mode to support USB-CDC flashing (ESP32-S2)
3. **Chip Info** — Chip description, features, and MAC address are read via efuse registers
4. **Stub Loading** — The ROM stub loader is uploaded and executed on the chip
5. **Baud Rate** — If upload baud rate ≠ 115200, it attempts the higher rate and falls back if unsupported
6. **Flash Size Detection** — Flash ID is read and mapped to a human-readable size
7. **Firmware Analysis** — The firmware binary header is parsed to determine flash mode and frequency; if a safeboot image is found at offset `0x10000`, it is flagged as a factory image
8. **Resource Assembly** (non-factory ESP32x only):
   - Bootloader ELF is downloaded (or loaded from cache) and converted to binary via `elf2image()`
   - Partition table is downloaded for the specific chip model
   - OTA data (`boot_app0.bin`) is downloaded
   - Safeboot image is downloaded from `ota.tasmota.com`
9. **Flash Layout** (non-factory ESP32x):
   - `0x0000` / `0x1000` / `0x2000` — Bootloader (offset varies by chip)
   - `0x8000` — Partition table
   - `0xE000` — OTA data
   - `0x10000` — Safeboot firmware
   - `0xE0000` — User firmware
10. **Erase** — Full flash erase (unless `--no-erase`)
11. **Write** — All binary segments are written with compressed transfer
12. **Reset** — Hard reset via RTS pin (or RTC WDT for USB-connected S2/S3 chips)
13. **Logs** — Serial output is displayed at 115200 baud

### Firmware Detection

The firmware type is detected by reading the first 4 bytes at two offsets:

| Offset | Magic Byte (`0xE9`) Found | Result |
|--------|--------------------------|--------|
| `0x10000` | Yes | **Factory image** — flashed as-is at offset `0x0` |
| `0x0` | Yes | **Standard firmware** — full resource assembly required |
| Neither | — | Error: invalid firmware binary |

### Bootloader & Partition Handling

Bootloader ELF files are fetched from GitHub and cached locally:

```
~/ESP_Flasher_<version>/bootloader/<model>/bin/bootloader_<flash_mode>_<flash_freq>.elf
```

The ELF is converted to a raw binary using the built-in `elf2image()` function. The resulting `.bin` is then written to flash at the chip-specific bootloader offset.

Partition tables and safeboot images are downloaded on every flash operation from:
- **Partitions:** `https://raw.githubusercontent.com/Jason2866/ESP_Flasher/factory/partitions/partitions.<model>.bin`
- **Safeboot:** `https://ota.tasmota.com/tasmota32/tasmota32<variant>-safeboot.bin`
- **OTA Data:** `https://raw.githubusercontent.com/Jason2866/ESP_Flasher/factory/partitions/boot_app0.bin`

### ANSI Color Support

ESP-Flasher includes full ANSI color code support in the terminal. The console can display:

- **Text formatting:** Bold, italic, underline, strikethrough
- **Foreground colors:** Black, red, green, yellow, blue, magenta, cyan, white
- **Background colors:** All standard 8 colors
- **Special features:** Secret text (redacted), carriage return handling for progress indicators

The implementation is in `esp_flasher/console_color.py` and uses Qt's `QTextCharFormat` to apply formatting. ANSI escape sequences are parsed using regex and converted to Qt text formatting in real-time.

**Example usage:**
```python
print("\033[32mSuccess!\033[0m")  # Green text
print("\033[1;31mError!\033[0m")  # Bold red text
```

For more details, see [ANSI_COLOR_SUPPORT.md](ANSI_COLOR_SUPPORT.md).

---

## Supported Flash Configurations

### Flash Sizes

| ID | Size | ID | Size |
|----|------|----|------|
| `0x12` | 256KB | `0x19` | 32MB |
| `0x13` | 512KB | `0x1A` | 64MB |
| `0x14` | 1MB | `0x1B` | 128MB |
| `0x15` | 2MB | `0x1C` | 256MB |
| `0x16` | 4MB | `0x20` | 64MB |
| `0x17` | 8MB | `0x21` | 128MB |
| `0x18` | 16MB | `0x22` | 256MB |

### Flash Modes

| Mode | Value |
|------|-------|
| QIO | `0x00` |
| QOUT | `0x01` |
| DIO | `0x02` |
| DOUT | `0x03` |

### Flash Frequencies

| Frequency | Value (ESP32) | Value (ESP8266) |
|-----------|--------------|-----------------|
| 40MHz | `0x0` | `0x0` |
| 26MHz | `0x1` | `0x1` |
| 20MHz | `0x2` | `0x2` |
| 80MHz | `0xF` | `0xF` |

### Bootloader Offsets per Chip

| Chip Model | Bootloader Offset | Notes |
|------------|------------------|-------|
| ESP8266 | `0x0000` | — |
| ESP32 | `0x1000` | — |
| ESP32-S2 | `0x1000` | — |
| ESP32-S3 | `0x0000` | — |
| ESP32-C2 | `0x0000` | Flash freq forced to 60MHz |
| ESP32-C3 | `0x0000` | — |
| ESP32-C5 | `0x2000` | — |
| ESP32-C6 | `0x0000` | Flash freq forced to 80MHz |
| ESP32-C61 | `0x0000` | Flash freq forced to 80MHz |
| ESP32-P4 | `0x2000` | Rev ≥ 3.0 uses `esp32p4rev3` model |

### Memory Layout (per Chip)

Each chip class defines a `MEMORY_MAP` with regions such as DROM, IROM, DRAM, IRAM, RTC_DATA, etc. These are used internally for ELF segment placement during `elf2image()` conversion.

---

## Building Standalone Binaries

**Build dependencies:**
```bash
pip install -r requirements.txt -r requirements_build.txt
pip install -e .
```

### macOS

```bash
python -m PyInstaller.__main__ -F -w -n ESP-Flasher -i icon.icns --add-data "esp_flasher/stubs/*.json:esp_flasher/stubs" esp_flasher/__main__.py
```

Or using a virtual environment:
```bash
/<path>/ESP_Flasher/.venv/bin/pyinstaller -F -w -n ESP-Flasher -i icon.icns --add-data "esp_flasher/stubs/*.json:esp_flasher/stubs" esp_flasher/__main__.py
```

The output is located at `dist/ESP-Flasher.app`.

### macOS (ARM)

Same command as macOS Intel — PyInstaller builds for the native architecture.

### Windows

```bash
python -m PyInstaller.__main__ -F -w -n ESP-Flasher -i icon.ico --add-data "esp_flasher/stubs/*.json;esp_flasher/stubs" esp_flasher\__main__.py
```

The output is located at `dist\ESP-Flasher.exe`.

### Linux (Ubuntu)

```bash
sudo apt install libnotify-dev libsdl2-dev
python -m PyInstaller.__main__ -F -w -n ESP-Flasher -i icon.ico --add-data "esp_flasher/stubs/*.json:esp_flasher/stubs" esp_flasher/__main__.py
```

The output is located at `dist/ESP-Flasher`.

---

## CI/CD

### Build Pipeline

The GitHub Actions workflow (`.github/workflows/build.yml`) is triggered on:
- Push of version tags (`v*.*.*`)
- Push to the `factory` branch
- Pull requests to `factory`
- Manual workflow dispatch

It builds binaries for four platforms in parallel:

| Job | Runner | Python | Output |
|-----|--------|--------|--------|
| `build-windows` | `windows-latest` | 3.13 | `ESP-Flasher.exe` |
| `build-ubuntu` | `ubuntu-latest` | 3.13 | `ESP-Flasher` (tar) |
| `build-macos` | `macos-15-intel` | 3.13 | `ESP-Flasher-macOS.app` (tar) |
| `build-macos-arm` | `macos-15` | 3.13 | `ESP-Flasher-macOSarm.app` (tar) |

On tagged releases, a `release` job uploads all artifacts to the GitHub Release.

### PyPI Publishing

The workflow `.github/workflows/build_pypi.yml` builds an sdist and wheel, then publishes to PyPI. Triggered on version tags or manual dispatch.

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| **No serial port found** | Check cable, install drivers, and on Linux add user to `dialout` group |
| **Antivirus flags the binary** | This is a [known false positive](https://github.com/pyinstaller/pyinstaller/issues/3802) with PyInstaller |
| **ESP not in flash boot mode** | Hold the BOOT/FLASH button on the board while connecting |
| **Baud rate not supported** | The tool automatically falls back to 115200 baud |
| **macOS driver issues** | Install the [Silicon Labs VCP Driver](https://www.silabs.com/documents/public/software/Mac_OSX_VCP_Driver.zip) |
| **Wrong boot mode detected** | Re-plug the device while holding the boot pin pressed |
| **No bootloader for flash frequency** | Frequencies 15MHz, 20MHz, 26MHz, and 30MHz are not supported for Tasmota bootloaders |
| **Invalid firmware binary** | Ensure the file starts with magic byte `0xE9` (ESP image format) |

---

## License

[MIT License](http://opensource.org/licenses/MIT) © Otto Winter, Michael Kandziora, Johann Obermeier

The embedded `own_esptool.py` is based on [esptool](https://github.com/espressif/esptool) by Espressif Systems, licensed under GPL-2.0-or-later.
