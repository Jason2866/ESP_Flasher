# ESP-Flasher

ESP-Flasher is a utility app for ESP8266 / ESP32 and is designed to make flashing ESPs as simple as possible by:

 * Having pre-built binaries for most operating systems.
 * Hiding all non-essential options for flashing. All necessary options for flashing
   (bootloader, flash mode) are automatically extracted from the binary.

The flashing process is done using the [esptool](https://github.com/espressif/esptool)
library by espressif.

## Installation

It doesn't have to be installed, just double-click it and it'll start.
Check the [releases section](https://github.com/Jason2866/ESP_Flasher/releases)
for downloads for your platform.

## Build it yourself

If you want to build this application yourself you need to:

- Install Python 3.x
- Install [wxPython 4.x](https://wxpython.org/) manually or run `pip3 install wxpython`
- Download this project and run `pip3 install -e .` in the project's root.
- Start the GUI using `esp_flasher`. Alternatively, you can use the command line interface (
  type `esp_flasher -h` for info)


## Linux Notes

Installing wxpython for linux can be a bit challenging (especially when you don't want to install from source).
You can use the following command to install a wxpython suitable with your OS:

```bash
# Go to https://extras.wxpython.org/wxPython4/extras/linux/gtk3/ and select the correct OS type
# here, we assume ubuntu 18.04 bionic
pip3 install -U \
    -f https://extras.wxpython.org/wxPython4/extras/linux/gtk3/ubuntu-18.04 \
    wxPython
```

