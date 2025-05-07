from __future__ import print_function

import argparse
from datetime import datetime
import sys
import time

import esp_flasher.own_esptool as esptool
from esp_flasher.own_esptool import get_port_list

import serial

from esp_flasher import const
from esp_flasher.common import (
    ESP32ChipInfo,
    Esp_flasherError,
    chip_run_stub,
    configure_write_flash_args,
    detect_chip,
    detect_flash_size,
    read_chip_info,
)
from esp_flasher.const import (
    ESP32_DEFAULT_BOOTLOADER_FORMAT,
    ESP32_DEFAULT_OTA_DATA,
    ESP32_SAFEBOOT_SERVER
)

def parse_args(argv):
    parser = argparse.ArgumentParser(prog=f"esp_flasher {const.__version__}")
    parser.add_argument("-p", "--port", help="Select the USB/COM port for uploading.")
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("--esp8266", action="store_true")
    group.add_argument("--esp32", action="store_true")
    group.add_argument("--esp32s2", action="store_true")
    group.add_argument("--esp32s3", action="store_true")
    group.add_argument("--esp32c2", action="store_true")
    group.add_argument("--esp32c3", action="store_true")
    group.add_argument("--esp32c5", action="store_true")
    group.add_argument("--esp32c6", action="store_true")
    group.add_argument("--esp32p4", action="store_true")
    group.add_argument(
        "--upload-baud-rate",
        type=int,
        default=1500000,
        help="Baud rate to upload (not for logging)",
    )
    parser.add_argument(
        "--bootloader",
        help="(ESP32x-only) The bootloader to flash.",
        default=ESP32_DEFAULT_BOOTLOADER_FORMAT,
    )
    parser.add_argument(
        "--safeboot",
        help="(ESP32x-only) The safeboot factory image to flash.",
    )
    parser.add_argument(
        "--input",
        help="(ESP32x-only) The bootloader elf file to flash.",
    )
    parser.add_argument(
        "--partitions",
        help="(ESP32x-only) The partitions to flash.",
    )
    parser.add_argument(
        "--otadata",
        help="(ESP32x-only) The otadata file to flash.",
        default=ESP32_DEFAULT_OTA_DATA,
    )
    parser.add_argument(
        "--no-erase", help="Do not erase flash before flashing", action="store_true"
    )
    parser.add_argument("--show-logs", help="Only show logs", action="store_true")
    parser.add_argument("binary", help="The binary image to flash.")

    return parser.parse_args(argv[1:])


def select_port(args):
    if args.port is not None:
        print(f"Using '{args.port}' as serial port.")
        return args.port
    ports = get_port_list()
    if not ports:
        raise Esp_flasherError("No serial port found!")
    if len(ports) != 1:
        print("Found more than one serial port:")
        for port in ports:
            print(f" * {port}")
        print("Please choose one with the --port argument.")
        raise Esp_flasherError
    print(f"Auto-detected serial port: {ports}")
    return ports


def show_logs(serial_port):
    print("Showing logs:")
    with serial_port:
        while True:
            try:
                raw = serial_port.readline()
            except serial.SerialException:
                print("Serial port closed!")
                return
            text = raw.decode(errors="ignore")
            line = text.replace("\r", "").replace("\n", "")
            time_ = datetime.now().time().strftime("[%H:%M:%S]")
            message = time_ + line
            try:
                print(message)
            except UnicodeEncodeError:
                print(message.encode("ascii", "backslashreplace"))


def run_esp_flasher(argv):
    args = parse_args(argv)
    port = select_port(args)

    if args.show_logs:
        serial_port = serial.Serial(port, baudrate=115200)
        show_logs(serial_port)
        return

    try:
        # pylint: disable=consider-using-with
        firmware = open(args.binary, "rb")
    except IOError as err:
        raise Esp_flasherError(f"Error opening binary: {err}") from err
    chip = detect_chip(port, args.esp8266, args.esp32)
    info = read_chip_info(chip)

    print()
    print("Chip Info:")
    print(f" - Chip Family: {info.family}")
    print(f" - Chip Model: {info.model}")
    if isinstance(info, ESP32ChipInfo):
        print(f" - Number of Cores: {info.num_cores}")
        print(f" - Max CPU Frequency: {info.cpu_frequency}")
        print(f" - Has Bluetooth: {'YES' if info.has_bluetooth else 'NO'}")
        print(f" - Has Embedded Flash: {'YES' if info.has_embedded_flash else 'NO'}")
        print(
            f" - Has Factory-Calibrated ADC: {'YES' if info.has_factory_calibrated_adc else 'NO'}"
        )
    else:
        print(f" - Chip ID: {info.chip_id:08X}")

    print(f" - MAC Address: {info.mac}")

    stub_chip = chip_run_stub(chip)
    flash_size = None

    if (args.upload_baud_rate != 115200) and ("ESP32" in info.family):
        try:
            stub_chip.change_baud(args.upload_baud_rate)
        except esptool.FatalError as err:
            raise Esp_flasherError(
                f"Error changing ESP upload baud rate: {err}"
            ) from err

        # Check if the higher baud rate works
        try:
            flash_size = detect_flash_size(stub_chip)
        except Esp_flasherError:
            # Go back to old baud rate by recreating chip instance
            print(
                f"Chip does not support baud rate {args.upload_baud_rate}, changing to 115200"
            )
            # pylint: disable=protected-access
            stub_chip._port.close()
            chip = detect_chip(port, args.esp8266, args.esp32)
            stub_chip = chip_run_stub(chip)

    if flash_size is None:
        flash_size = detect_flash_size(stub_chip)

    print(f" - Flash Size: {flash_size}")

    flag_factory = False
    min_rev = 0
    min_rev_full = 0
    max_rev_full = 65535
    secure_pad = "False"
    secure_pad_v2 = "False"
    elf_sha256_offset = ""
    use_segments = ""
    flash_mmu_page_size = ""
    pad_to_size = ""
    spi_connection = ""
    output = ""

    mock_args = configure_write_flash_args(
        info, chip, flag_factory, args.safeboot, firmware, flash_size, args.bootloader, args.partitions, args.otadata,
        args.input, secure_pad, secure_pad_v2, min_rev, min_rev_full, max_rev_full, elf_sha256_offset,
        use_segments, flash_mmu_page_size, pad_to_size, spi_connection, output
    )
    if (not "ESP8266" in info.family) and (not mock_args.flag_factory):
        try:
            esptool.elf2image(mock_args)
        except esptool.FatalError as err:
            raise Esp_flasherError(f"Error while converting elf to bin: {err}") from err

        mock_args = configure_write_flash_args(
            info, chip, flag_factory, args.safeboot, firmware, flash_size, args.bootloader, args.partitions, args.otadata,
            args.input, secure_pad, secure_pad_v2, min_rev, min_rev_full, max_rev_full, elf_sha256_offset,
            use_segments, flash_mmu_page_size, pad_to_size, spi_connection, output
        )

    #print(f" - Flash Mode: {mock_args.flash_mode}")
    #print(f" - Flash Frequency: {mock_args.flash_freq.upper()}Hz")

    try:
        stub_chip.flash_set_parameters(esptool.flash_size_bytes(flash_size))
    except esptool.FatalError as err:
        raise Esp_flasherError(f"Error setting flash parameters: {err}") from err

    if not args.no_erase:
        try:
            esptool.erase_flash(stub_chip, mock_args)
        except esptool.FatalError as err:
            raise Esp_flasherError(f"Error while erasing flash: {err}") from err

    try:
        esptool.write_flash(stub_chip, mock_args)
    except esptool.FatalError as err:
        raise Esp_flasherError(f"Error while writing flash: {err}") from err

    print("Hard Resetting...")
    stub_chip.hard_reset()

    print("Done! Flashing is complete!")
    print()

    if args.upload_baud_rate != 115200:
        # pylint: disable=protected-access
        stub_chip._port.baudrate = 115200
        time.sleep(0.05)  # get rid of crap sent during baud rate change
        # pylint: disable=protected-access
        stub_chip._port.flushInput()

    # pylint: disable=protected-access
    show_logs(stub_chip._port)


def main():
    try:
        if len(sys.argv) <= 1:
            from esp_flasher import gui

            return gui.main() or 0
        return run_esp_flasher(sys.argv) or 0
    except Esp_flasherError as err:
        msg = str(err)
        if msg:
            print(msg)
        return 1
    except KeyboardInterrupt:
        return 1


if __name__ == "__main__":
    sys.exit(main())
