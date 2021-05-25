# ESP-Flasher

[![GitHub Releases](https://img.shields.io/github/downloads/Jason2866/ESP_Flasher/total?label=downloads&color=%231FA3EC&style=for-the-badge)](https://github.com/Jason2866/ESP_Flasher/releases/latest)

ESP-Flasher is a utility app for ESP8266 / ESP32 and is designed to make flashing Tasmota on ESPs as simple as possible by:

 * Having pre-built binaries for most operating systems.
 * Hiding all non-essential options for flashing. All necessary options for flashing
   (bootloader, flash mode) are automatically extracted from the binary.

The flashing process is done using the [esptool](https://github.com/espressif/esptool)
library by espressif.

## Installation

It doesn't have to be installed, just double-click it and it'll start.
Check the [releases section](https://github.com/Jason2866/ESP_Flasher/releases)
for downloads for your platform.

If you have Python installed you can install from PyPI: **`pip install esp-flasher`**

## Build it yourself

If you want to build this application yourself you need to:

- Install Python 3.x
- Install [wxPython 4.x](https://wxpython.org/) manually or run `pip3 install wxpython`
- Download this project and run `pip3 install -e .` in the project's root.
- Start the GUI using `esp_flasher`. Alternatively, you can use the command line interface (
  type `esp_flasher -h` for info)

### Mac OSX Big Sur Drivers

Some info and link to download the latest driver needed for Mac OSX Big Sur.

Info: https://www.silabs.com/community/interface/forum.topic.html/vcp_driver_for_macosbigsur110x-krlP

Driver: https://www.silabs.com/documents/public/software/Mac_OSX_VCP_Driver.zip


## Linux Notes

Installing wxpython for linux can be a bit challenging (especially when you don't want to install from source).
You can use the following command to install a wxpython suitable with your OS:

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
