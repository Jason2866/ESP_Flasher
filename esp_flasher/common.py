import io
import struct

import esp_flasher.own_esptool as esptool

from esp_flasher.const import (
    ESP32_DEFAULT_PARTITIONS,
    HTTP_REGEX,
)
from esp_flasher.helpers import prevent_print


class Esp_flasherError(Exception):
    pass


class MockEsptoolArgs:
    def __init__(self, flash_size, addr_filename, flash_mode, flash_freq):
        self.compress = True
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
        has_bluetooth = "BT" in features
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
    header = firmware.read(4)
    firmware.seek(0)

    magic, _, flash_mode_raw, flash_size_freq = struct.unpack("BBBB", header)
    if magic != esptool.ESPLoader.ESP_IMAGE_MAGIC:
        raise Esp_flasherError(
            f"The firmware binary is invalid (magic byte={magic:02X}, should be {esptool.ESPLoader.ESP_IMAGE_MAGIC:02X})"
        )
    flash_freq_raw = flash_size_freq & 0x0F
    flash_mode = {0: "qio", 1: "qout", 2: "dio", 3: "dout"}.get(flash_mode_raw)
    flash_freq = {0: "40m", 1: "26m", 2: "20m", 0xF: "80m"}.get(flash_freq_raw)
    return flash_mode, flash_freq


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
    info, firmware_path, flash_size, bootloader_path, partitions_path, otadata_path
):
    addr_filename = []
    firmware = open_downloadable_binary(firmware_path)
    flash_mode, flash_freq = read_firmware_info(firmware)
    if isinstance(info, ESP32ChipInfo):
        ofs_partitions = 0x8000
        ofs_otadata = 0xe000
        ofs_firmware = 0x10000

        if "ESP32-C3" in info.model:
            model = "esp32c3"
            ofs_bootloader = 0x0
        elif "ESP32-S3" in info.model:
            model = "esp32s3"
            ofs_bootloader = 0x0
        elif "ESP32-S2" in info.model:
            model = "esp32s2"
            ofs_bootloader = 0x1000
        else:
            model = "esp32"
            ofs_bootloader = 0x1000

        if flash_freq in ("26m", "20m"):
            raise Esp_flasherError(
                f"No bootloader available for flash frequency {flash_freq}"
            )
        bootloader = open_downloadable_binary(
            format_bootloader_path(bootloader_path, model, flash_mode, flash_freq)
        )

        if not partitions_path:
            partitions_path = format_partitions_path(ESP32_DEFAULT_PARTITIONS, model)

        partitions = open_downloadable_binary(partitions_path)
        otadata = open_downloadable_binary(otadata_path)

        addr_filename.append((ofs_bootloader, bootloader))
        addr_filename.append((ofs_partitions, partitions))
        addr_filename.append((ofs_otadata, otadata))
        addr_filename.append((ofs_firmware, firmware))
    else:
        addr_filename.append((0x0, firmware))
    return MockEsptoolArgs(flash_size, addr_filename, flash_mode, flash_freq)


def detect_chip(port, force_esp8266=False, force_esp32=False):
    if force_esp8266 or force_esp32:
        klass = esptool.ESP32ROM if force_esp32 else esptool.ESP8266ROM
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
        chip.connect()
    except esptool.FatalError as err:
        raise Esp_flasherError(f"Error connecting to ESP: {err}") from err

    return chip
