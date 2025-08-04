import re

__version__ = "3.1.0"

ESP32_DEFAULT_OTA_DATA = (
    "https://raw.githubusercontent.com/Jason2866/ESP_Flasher/factory/"
    "partitions/boot_app0.bin"
)
ESP32_DEFAULT_BOOTLOADER_FORMAT = (
    "https://raw.githubusercontent.com/Jason2866/ESP_Flasher/factory/"
    "bootloader/$MODEL$/bin/bootloader_$FLASH_MODE$_$FLASH_FREQ$.elf"
)
ESP32_DEFAULT_PARTITIONS = (
    "https://raw.githubusercontent.com/Jason2866/ESP_Flasher/factory/"
    "partitions/partitions.$MODEL$.bin"
)
ESP32_SAFEBOOT_SERVER = (
    "https://ota.tasmota.com/tasmota32/"
)

# https://stackoverflow.com/a/3809435/8924614
HTTP_REGEX = re.compile(
    r"https?://(www\.)?[-a-zA-Z0-9@:%._+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_+.~#?&/=]*)"
)
