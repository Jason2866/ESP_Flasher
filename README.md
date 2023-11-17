[![Build_special_firmware](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/banner-direct.svg)](https://github.com/vshymanskyy/StandWithUkraine/blob/main/docs/README.md)


# Tasmota-ESP-Flasher for Tasmota v13 and later (Safeboot partition scheme)

[![GitHub Releases](https://img.shields.io/github/downloads/Jason2866/ESP_Flasher/total?label=downloads&color=%231FA3EC&style=for-the-badge)](https://github.com/Jason2866/ESP_Flasher/releases/latest)

Tasmota-ESP-Flasher is an app for ESP8266 / ESP32 designed to make flashing Tasmota on ESPs as simple as possible by:

 * Pre-built binaries for most used operating systems
 * Support for Tasmota factory images 
 * Hiding all non-essential options for flashing
 * All necessary options (bootloader, flash mode, safeboot) are set automatically.

The flashing process is done using [esptool](https://github.com/espressif/esptool) from espressif.

## Installation

- Check the [releases section](https://github.com/Jason2866/ESP_Flasher/releases) for your OS.
- Download and double-click and it'll start.

- The native Python version can be installed from PyPI: **`pip install esp-flasher`**.
  Start the GUI by `esp_flasher`. Alternatively, you can use the command line interface ( type `esp_flasher -h` for info)

## Build it yourself

If you want to build this application yourself you need to:

- Install Python 3.x
- Install [wxPython 4.x](https://wxpython.org/) manually or run `pip3 install wxpython`
- Download this project and run `pip3 install -e .` in the project's root.
- Start the GUI using `esp_flasher`. Alternatively, you can use the command line interface (
  type `esp_flasher -h` for info)

### Mac OSX (compiled binary only for 11 and newer)

Driver maybe needed for Mac OSx.

Info: https://www.silabs.com/community/interface/forum.topic.html/vcp_driver_for_macosbigsur110x-krlP

Driver: https://www.silabs.com/documents/public/software/Mac_OSX_VCP_Driver.zip


## Linux Notes

Installing wxpython for linux can be a bit challenging (especially when you don't want to install from source).
You can use the following command to install a wxpython suitable with your OS and Python version:

```bash
# Go to https://extras.wxpython.org/wxPython4/extras/linux/gtk3/ and select the correct OS type
# here, we assume ubuntu 20.04
         sudo apt-get update
         sudo apt install libgtk-3-dev libnotify-dev libsdl2-dev
         pip3 install -U \
          -f https://extras.wxpython.org/wxPython4/extras/linux/gtk3/ubuntu-20.04 \
          wxPython
```

## License

[MIT](http://opensource.org/licenses/MIT) © Marcel Stör, Otto Winter, Johann Obermeier

