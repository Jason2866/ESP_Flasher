import os
import io
import struct
from os.path import join
from io import BytesIO

import esp_flasher.own_esptool as esptool

from esp_flasher.const import (
    ESP32_DEFAULT_PARTITIONS,
    ESP32_SAFEBOOT_SERVER,
    HTTP_REGEX,
    __version__,
)
from esp_flasher.helpers import prevent_print


class Esp_flasherError(Exception):
    pass


class MockEsptoolArgs:
    def __init__(self, chip, flag_factory, flash_size, addr_filename, flash_mode, flash_freq, input, secure_pad, secure_pad_v2,
        min_rev, min_rev_full, max_rev_full, elf_sha256_offset, use_segments, flash_mmu_page_size, pad_to_size, spi_connection, output):
        self.compress = True
        self.chip = chip
        self.flag_factory = flag_factory
        self.no_compress = False
        self.flash_size = flash_size
        self.addr_filename = addr_filename
        self.flash_mode = flash_mode
        self.flash_freq = flash_freq
        self.no_stub = False
        self.verify = False
        self.erase_all = False
        self.encrypt = False
        self.encrypt_files = None
        self.input = input
        self.secure_pad = False
        self.secure_pad_v2 = False
        self.min_rev = 0
        self.min_rev_full = 0
        self.max_rev_full = 65535
        self.elf_sha256_offset = ""
        self.use_segments = "False"
        self.flash_mmu_page_size = ""
        self.pad_to_size = ""
        self.spi_connection = ""
        self.output = output

class ChipInfo:
    def __init__(self, family, model, mac):
        self.family = family
        self.model = model
        self.mac = mac
        self.is_esp32 = None

    def as_dict(self):
        return {
            "family": self.family,
            "model": self.model,
            "mac": self.mac,
            "is_esp32": self.is_esp32,
        }


class ESP32ChipInfo(ChipInfo):
    def __init__(
        self,
        model,
        mac,
        num_cores,
        cpu_frequency,
        has_bluetooth,
        has_embedded_flash,
        has_factory_calibrated_adc,
    ):
        super().__init__("ESP32", model, mac)
        self.num_cores = num_cores
        self.cpu_frequency = cpu_frequency
        self.has_bluetooth = has_bluetooth
        self.has_embedded_flash = has_embedded_flash
        self.has_factory_calibrated_adc = has_factory_calibrated_adc

    def as_dict(self):
        data = ChipInfo.as_dict(self)
        data.update(
            {
                "num_cores": self.num_cores,
                "cpu_frequency": self.cpu_frequency,
                "has_bluetooth": self.has_bluetooth,
                "has_embedded_flash": self.has_embedded_flash,
                "has_factory_calibrated_adc": self.has_factory_calibrated_adc,
            }
        )
        return data


class ESP8266ChipInfo(ChipInfo):
    def __init__(self, model, mac, chip_id):
        super().__init__("ESP8266", model, mac)
        self.chip_id = chip_id

    def as_dict(self):
        data = ChipInfo.as_dict(self)
        data.update(
            {
                "chip_id": self.chip_id,
            }
        )
        return data


def read_chip_property(func, *args, **kwargs):
    try:
        return prevent_print(func, *args, **kwargs)
    except esptool.FatalError as err:
        raise Esp_flasherError(f"Reading chip details failed: {err}") from err


def read_chip_info(chip):
    mac = ":".join(f"{x:02X}" for x in read_chip_property(chip.read_mac))
    if isinstance(chip, esptool.ESP32ROM):
        model = read_chip_property(chip.get_chip_description)
        features = read_chip_property(chip.get_chip_features)
        num_cores = 2 if "Dual Core" in features else 1
        frequency = next((x for x in ("160MHz", "240MHz") if x in features), "80MHz")
        has_bluetooth = "BLE" in features or "BT" in features or "BT 5" in features
        has_embedded_flash = "Embedded Flash" in features
        has_factory_calibrated_adc = "VRef calibration in efuse" in features
        return ESP32ChipInfo(
            model,
            mac,
            num_cores,
            frequency,
            has_bluetooth,
            has_embedded_flash,
            has_factory_calibrated_adc,
        )
    if isinstance(chip, esptool.ESP8266ROM):
        model = read_chip_property(chip.get_chip_description)
        chip_id = read_chip_property(chip.chip_id)
        return ESP8266ChipInfo(model, mac, chip_id)
    raise Esp_flasherError(f"Unknown chip type {type(chip)}")


def chip_run_stub(chip):
    try:
        return chip.run_stub()
    except esptool.FatalError as err:
        raise Esp_flasherError(
            f"Error putting ESP in stub flash mode: {err}"
        ) from err


def detect_flash_size(stub_chip):
    flash_id = read_chip_property(stub_chip.flash_id)
    return esptool.DETECTED_FLASH_SIZES.get(flash_id >> 16, "4MB")


def read_firmware_info(firmware):
    firmware.seek(0x10000)  # Check for safeboot image
    header = firmware.read(4)
    magic, _, flash_mode_raw, flash_size_freq = struct.unpack("BBBB", header)
    if magic == esptool.ESPLoader.ESP_IMAGE_MAGIC:
        flash_freq_raw = flash_size_freq & 0x0F
        flash_mode = {0: "qio", 1: "qout", 2: "dio", 3: "dout"}.get(flash_mode_raw)
        flash_freq = {0: "40m", 1: "26m", 2: "20m", 0xF: "80m"}.get(flash_freq_raw)
        flag_factory = True
        return flash_mode, flash_freq, flag_factory

    firmware.seek(0)  # Check for firmware image
    header = firmware.read(4)
    magic, _, flash_mode_raw, flash_size_freq = struct.unpack("BBBB", header)
    if magic == esptool.ESPLoader.ESP_IMAGE_MAGIC:
        flash_freq_raw = flash_size_freq & 0x0F
        flash_mode = {0: "qio", 1: "qout", 2: "dio", 3: "dout"}.get(flash_mode_raw)
        flash_freq = {0: "40m", 1: "26m", 2: "20m", 0xF: "80m"}.get(flash_freq_raw)
        flag_factory = False
        return flash_mode, flash_freq, flag_factory

    if magic != esptool.ESPLoader.ESP_IMAGE_MAGIC:
        raise Esp_flasherError(
            f"The firmware binary is invalid (magic byte={magic:02X}, should be {esptool.ESPLoader.ESP_IMAGE_MAGIC:02X})"
        )



def open_downloadable_binary(path):
    if hasattr(path, "seek"):
        path.seek(0)
        return path

    if HTTP_REGEX.match(path) is not None:
        import requests

        try:
            response = requests.get(path)
            response.raise_for_status()
        except requests.exceptions.Timeout as err:
            raise Esp_flasherError(
                f"Timeout while retrieving firmware file '{path}': {err}"
            ) from err
        except requests.exceptions.RequestException as err:
            raise Esp_flasherError(
                f"Error while retrieving firmware file '{path}': {err}"
            ) from err

        binary = io.BytesIO()
        binary.write(response.content)
        binary.seek(0)
        return binary

    try:
        return open(path, "rb")
    except IOError as err:
        raise Esp_flasherError(f"Error opening binary '{path}': {err}") from err

def format_bootloader_path(path, model, flash_mode, flash_freq):
    return path.replace("$MODEL$", model).replace("$FLASH_MODE$", flash_mode).replace("$FLASH_FREQ$", flash_freq)


def format_partitions_path(path, model):
    return path.replace("$MODEL$", model)


def configure_write_flash_args(
    info, chip, flag_factory, factory_firm_path, firmware_path, flash_size, bootloader_path, partitions_path, otadata_path, input, secure_pad, secure_pad_v2,
    min_rev, min_rev_full, max_rev_full, elf_sha256_offset, use_segments, flash_mmu_page_size, pad_to_size, spi_connection, output
):
    addr_filename = []
    firmware = open_downloadable_binary(firmware_path)
    flash_mode, flash_freq, flag_factory = read_firmware_info(firmware)
    if flag_factory:
        print("Detected factory firmware Image, flashing without changes")
    if (isinstance(info, ESP32ChipInfo)):  # No esp8266 image, fetching and processing needed files
        ofs_partitions = 0x8000
        ofs_otadata = 0xe000
        ofs_factory_firm = 0x10000
        ofs_firmware = 0xe0000

        if "ESP32-C2" in info.model:
            model = "esp32c2"
            safeboot = "tasmota32c2-safeboot.bin"
            ofs_bootloader = 0x0
            flash_freq = "60m"  # For Tasmota we use only fastest
        elif "ESP32-C3" in info.model:
            model = "esp32c3"
            safeboot = "tasmota32c3-safeboot.bin"
            ofs_bootloader = 0x0
        elif "ESP32-C5" in info.model:
            model = "esp32c5"
            safeboot = "tasmota32c5-safeboot.bin"
            ofs_bootloader = 0x2000
        elif "ESP32-C6" in info.model:
            model = "esp32c6"
            safeboot = "tasmota32c6-safeboot.bin"
            ofs_bootloader = 0x0
            flash_freq = "80m"  # For Tasmota we use only fastest
        elif "ESP32-P4" in info.model:
            model = "esp32p4"
            safeboot = "tasmota32p4-safeboot.bin"
            ofs_bootloader = 0x2000
        elif "ESP32-S3" in info.model:
            model = "esp32s3"
            safeboot = "tasmota32s3-safeboot.bin"
            ofs_bootloader = 0x0
        elif "ESP32-S2" in info.model:
            model = "esp32s2"
            safeboot = "tasmota32s2-safeboot.bin"
            ofs_bootloader = 0x1000
        else:
            model = "esp32"
            safeboot = "tasmota32solo1-safeboot.bin"
            ofs_bootloader = 0x1000

        if flash_freq in ("15", "20m", "26m", "30"):
            raise Esp_flasherError(
                f"No bootloader available for flash frequency {flash_freq}"
            )
        chip = model
        min_rev = 0
        min_rev_full = 0
        max_rev_full = 65535
        secure_pad = "False"
        secure_pad_v2 = "False"
        elf_sha256_offset = ""
        use_segments = "False"
        flash_mmu_page_size = ""
        pad_to_size = ""
        spi_connection = ""

        if (isinstance(info, ESP32ChipInfo)) and not flag_factory:   # esp32 and no factory image
            uwd = os.path.expanduser("~")
            esp_flasher_ver = "ESP_Flasher_" + __version__
            bootloaderstring = "bootloader_" + flash_mode + "_" + flash_freq + ".elf"
            boot_loader_path = join(uwd, esp_flasher_ver, "bootloader", model, "bin")
            boot_loader_file = join(boot_loader_path , bootloaderstring)
            if not os.path.exists(boot_loader_path):
                os.makedirs(boot_loader_path)
            output = boot_loader_file.replace(".elf", ".bin")

            try:
                open(boot_loader_file, "rb")    # check for local elf bootloader file
            except IOError as err:              # download elf bootloader file
                boot_elf_path = open_downloadable_binary(
                    format_bootloader_path(bootloader_path, model, flash_mode, flash_freq)
                )
                with open(boot_loader_file, "wb") as f:
                    f.write(boot_elf_path.getbuffer())  # save elf bootloader file local

            try:
                with open(output, "rb") as fh:
                    bootloader = BytesIO(fh.read())
            except IOError as err:
                bootloader=""           # Will be there in second call!

            input = boot_loader_file    # local downloaded elf bootloader file
            if not partitions_path:
                partitions_path = format_partitions_path(ESP32_DEFAULT_PARTITIONS, model)
            if not factory_firm_path:
                factory_firm_path = ESP32_SAFEBOOT_SERVER + safeboot

            partitions = open_downloadable_binary(partitions_path)
            factory_firm = open_downloadable_binary(factory_firm_path)
            otadata = open_downloadable_binary(otadata_path)
            # add all needed files since only firmware is provided
            addr_filename.append((ofs_bootloader, bootloader))
            addr_filename.append((ofs_partitions, partitions))
            addr_filename.append((ofs_otadata, otadata))
            addr_filename.append((ofs_factory_firm, factory_firm))
            addr_filename.append((ofs_firmware, firmware))
        else:
            addr_filename.append((0x0, firmware))  # esp32 factory image
    else:
        addr_filename.append((0x0, firmware))      # esp8266 image
    return MockEsptoolArgs(chip, flag_factory, flash_size, addr_filename, flash_mode, flash_freq, input, secure_pad, secure_pad_v2,
                           min_rev, min_rev_full, max_rev_full, elf_sha256_offset, use_segments, flash_mmu_page_size, pad_to_size, spi_connection, output)


def detect_chip(port, force_esp8266=False, force_esp32=False, force_esp32s2=False, force_esp32s3=False, force_esp32c2=False, force_esp32c3=False, force_esp32c5=False, force_esp32c6=False, force_esp32p4=False):
    if force_esp8266 or force_esp32 or force_esp32s2 or force_esp32s3 or force_esp32c2 or force_esp32c3 or force_esp32c5 or force_esp32c6 or force_esp32p4:
        if force_esp8266:
            klass = esptool.ESP8266ROM
        elif force_esp32:
            klass = esptool.ESP32ROM
        elif force_esp32s2:
            klass = esptool.ESP32S2ROM
        elif force_esp32s3:
            klass = esptool.ESP32S3ROM
        elif force_esp32c2:
            klass = esptool.ESP32C2ROM
        elif force_esp32c3:
            klass = esptool.ESP32C3ROM
        elif force_esp32c5:
            klass = esptool.ESP32C5ROM
        elif force_esp32c6:
            klass = esptool.ESP32C6ROM
        elif force_esp32p4:
            klass = esptool.ESP32P4ROM
        chip = klass(port)
    else:
        try:
            chip = esptool.ESPLoader.detect_chip(port)
        except esptool.FatalError as err:
            if "Wrong boot mode detected" in str(err):
                msg = "ESP is not in flash boot mode. If your board has a flashing pin, try again while keeping it pressed."
            else:
                msg = f"ESP Chip Auto-Detection failed: {err}"
            raise Esp_flasherError(msg) from err

    try:
        # connect(mode='default_reset', attempts=DEFAULT_CONNECT_ATTEMPTS (7), detecting=False, warnings=True)
        # no_reset is used to stay in bootloader -> fix for S2 CDC flashing
        chip.connect('no_reset',7,False,False)
    except esptool.FatalError as err:
        raise Esp_flasherError(f"Error connecting to ESP: {err}") from err

    return chip
