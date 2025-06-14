
[![Build_special_firmware](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/banner-direct.svg)](https://github.com/vshymanskyy/StandWithUkraine/blob/main/docs/README.md)

# Tasmota-ESP-Flasher for Tasmota v13 and later (Safeboot partition scheme)

[![GitHub Releases](https://img.shields.io/github/downloads/Jason2866/ESP_Flasher/total?label=downloads&color=%231FA3EC&style=for-the-badge)](https://github.com/Jason2866/ESP_Flasher/releases/latest)

Tasmota-ESP-Flasher is an app for ESP8266 / ESP32 designed to make flashing Tasmota on ESPs as simple as possible by:

 * Pre-built binaries for most used operating systems
 * Support for Tasmota factory images
 * Hiding all non-essential options for flashing
 * All necessary options (bootloader, flash mode, safeboot) are set automatically
 * Flashing is lightning fast

The flashing process is done using [esptool](https://github.com/espressif/esptool) from espressif.

## Installation

- Check the [releases section](https://github.com/Jason2866/ESP_Flasher/releases) for your OS.
- Download and double-click and it'll start.

- The native Python version can be installed from PyPI: **`pip install esp-flasher`**.
  Start the GUI by `esp_flasher`. Alternatively, you can use the command line interface ( type `esp_flasher -h` for info)

In the odd case of your antivirus going haywire over that application, it's a [false positive.](https://github.com/pyinstaller/pyinstaller/issues/3802)

## Documentation
[Tasmota ESP Flasher Wiki](https://deepwiki.com/Jason2866/ESP_Flasher)

## Build it yourself

If you want to build this application yourself you need to:

- Install Python 3.x
- Download this project and run `pip3 install -e .` in the project's root.
- Start the GUI using `esp_flasher`. Alternatively, you can use the command line interface (
  type `esp_flasher -h` for info)

### Mac OSX (compiled binary only for 11 and newer)

Driver maybe needed for Mac OSx.

Info: https://www.silabs.com/community/interface/forum.topic.html/vcp_driver_for_macosbigsur110x-krlP

Driver: https://www.silabs.com/documents/public/software/Mac_OSX_VCP_Driver.zip

## License

[MIT](http://opensource.org/licenses/MIT) © Otto Winter, Michael Kandziora, Johann Obermeier

### Powered by
[![CLion logo.](https://resources.jetbrains.com/storage/products/company/brand/logos/CLion.svg)](https://jb.gg/OpenSourceSupport)
