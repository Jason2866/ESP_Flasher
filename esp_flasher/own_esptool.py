#!/usr/bin/env python
#
# SPDX-FileCopyrightText: 2014-2022 Fredrik Ahlberg, Angus Gratton, Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import division, print_function
from typing import Dict

import argparse
import base64
import binascii
import copy
import hashlib
import inspect
import io
import itertools
import os
import re
import shlex
import string
import struct
import sys
import time
import zlib

try:
    import serial
except ImportError:
    print("Pyserial is not installed for %s. Check the README for installation instructions." % (sys.executable))
    raise

# check 'serial' is 'pyserial' and not 'serial' https://github.com/espressif/esptool/issues/269
try:
    if "serialization" in serial.__doc__ and "deserialization" in serial.__doc__:
        raise ImportError("""
esptool.py depends on pyserial, but there is a conflict with a currently installed package named 'serial'.

You may be able to work around this by 'pip uninstall serial; pip install pyserial' \
but this may break other installed Python software that depends on 'serial'.

There is no good fix for this right now, apart from configuring virtualenvs. \
See https://github.com/espressif/esptool/issues/269#issuecomment-385298196 for discussion of the underlying issue(s).""")
except TypeError:
    pass  # __doc__ returns None for pyserial

try:
    import serial.tools.list_ports as list_ports
except ImportError:
    print("The installed version (%s) of pyserial appears to be too old for esptool.py (Python interpreter %s). "
          "Check the README for installation instructions." % (sys.VERSION, sys.executable))
    raise
except Exception:
    if sys.platform == "darwin":
        # swallow the exception, this is a known issue in pyserial+macOS Big Sur preview ref https://github.com/espressif/esptool/issues/540
        list_ports = None
    else:
        raise


__version__ = "3.6.0"

MAX_UINT32 = 0xffffffff
MAX_UINT24 = 0xffffff

DEFAULT_TIMEOUT = 3                   # timeout for most flash operations
START_FLASH_TIMEOUT = 20              # timeout for starting flash (may perform erase)
CHIP_ERASE_TIMEOUT = 120              # timeout for full chip erase
MAX_TIMEOUT = CHIP_ERASE_TIMEOUT * 2  # longest any command can run
SYNC_TIMEOUT = 0.1                    # timeout for syncing with bootloader
MD5_TIMEOUT_PER_MB = 8                # timeout (per megabyte) for calculating md5sum
ERASE_REGION_TIMEOUT_PER_MB = 30      # timeout (per megabyte) for erasing a region
ERASE_WRITE_TIMEOUT_PER_MB = 40       # timeout (per megabyte) for erasing and writing data
MEM_END_ROM_TIMEOUT = 0.05            # special short timeout for ESP_MEM_END, as it may never respond
DEFAULT_SERIAL_WRITE_TIMEOUT = 10     # timeout for serial port write
DEFAULT_CONNECT_ATTEMPTS = 7          # default number of times to try connection
WRITE_BLOCK_ATTEMPTS = 3              # number of times to try writing a data block

SUPPORTED_CHIPS = ['esp8266', 'esp32', 'esp32s2', 'esp32s3', 'esp32c2', 'esp32c3', 'esp32c5', 'esp32c6', 'esp32c61', 'esp32h2', 'esp32p4']

def timeout_per_mb(seconds_per_mb, size_bytes):
    """ Scales timeouts which are size-specific """
    result = seconds_per_mb * (size_bytes / 1e6)
    if result < DEFAULT_TIMEOUT:
        return DEFAULT_TIMEOUT
    return result


def _chip_to_rom_loader(chip):
    return {
        'esp8266': ESP8266ROM,
        'esp32': ESP32ROM,
        'esp32s2': ESP32S2ROM,
        'esp32s3': ESP32S3ROM,
        'esp32p4': ESP32P4ROM,
        'esp32c3': ESP32C3ROM,
        'esp32c5': ESP32C5ROM,
        'esp32c6': ESP32C6ROM,
        'esp32c61': ESP32C61ROM,
        'esp32h2': ESP32H2ROM,
        'esp32c2': ESP32C2ROM,
    }[chip]


def get_default_connected_device(serial_list, port, connect_attempts, initial_baud, chip='auto', trace=False,
                                 before='default_reset'):
    _esp = None
    for each_port in reversed(serial_list):
        print("Serial port %s" % each_port)
        try:
            if chip == 'auto':
                _esp = ESPLoader.detect_chip(each_port, initial_baud, before, trace,
                                             connect_attempts)
            else:
                chip_class = _chip_to_rom_loader(chip)
                _esp = chip_class(each_port, initial_baud, trace)
                _esp.connect(before, connect_attempts)
            break
        except (FatalError, OSError) as err:
            if port is not None:
                raise
            print("%s failed to connect: %s" % (each_port, err))
            if _esp and _esp._port:
                _esp._port.close()
            _esp = None
    return _esp


DETECTED_FLASH_SIZES = {
    0x12: "256KB",
    0x13: "512KB",
    0x14: "1MB",
    0x15: "2MB",
    0x16: "4MB",
    0x17: "8MB",
    0x18: "16MB",
    0x19: "32MB",
    0x1A: "64MB",
    0x1B: "128MB",
    0x1C: "256MB",
    0x20: "64MB",
    0x21: "128MB",
    0x22: "256MB",
    0x32: "256KB",
    0x33: "512KB",
    0x34: "1MB",
    0x35: "2MB",
    0x36: "4MB",
    0x37: "8MB",
    0x38: "16MB",
    0x39: "32MB",
    0x3A: "64MB",
}


def check_supported_function(func, check_func):
    """
    Decorator implementation that wraps a check around an ESPLoader
    bootloader function to check if it's supported.

    This is used to capture the multidimensional differences in
    functionality between the ESP8266 & ESP32 (and later chips) ROM loaders, and the
    software stub that runs on these. Not possible to do this cleanly
    via inheritance alone.
    """
    def inner(*args, **kwargs):
        obj = args[0]
        if check_func(obj):
            return func(*args, **kwargs)
        else:
            raise NotImplementedInROMError(obj, func)
    return inner


def esp8266_function_only(func):
    """ Attribute for a function only supported on ESP8266 """
    return check_supported_function(func, lambda o: o.CHIP_NAME == "ESP8266")


def stub_function_only(func):
    """ Attribute for a function only supported in the software stub loader """
    return check_supported_function(func, lambda o: o.IS_STUB)


def stub_and_esp32_function_only(func):
    """ Attribute for a function only supported by software stubs or ESP32 and later chips ROM """
    return check_supported_function(func, lambda o: o.IS_STUB or isinstance(o, ESP32ROM))


def esp32s3_or_newer_function_only(func):
    """ Attribute for a function only supported by ESP32S3 and later chips ROM """
    return check_supported_function(func, lambda o: isinstance(o, ESP32S3ROM) or isinstance(o, ESP32C3ROM))


PYTHON2 = sys.version_info[0] < 3  # True if on pre-Python 3


def byte(bitstr, index):
    return bitstr[index]

# Provide a 'basestring' class on Python 3
try:
    basestring
except NameError:
    basestring = str


def print_overwrite(message, last_line=False):
    """ Print a message, overwriting the currently printed line.

    If last_line is False, don't append a newline at the end (expecting another subsequent call will overwrite this one.)

    After a sequence of calls with last_line=False, call once with last_line=True.

    If output is not a TTY (for example redirected a pipe), no overwriting happens and this function is the same as print().
    """
    if sys.stdout.isatty():
        print("\r%s" % message, end='\n' if last_line else '')
    else:
        print(message)


def _mask_to_shift(mask):
    """ Return the index of the least significant bit in the mask """
    shift = 0
    while mask & 0x1 == 0:
        shift += 1
        mask >>= 1
    return shift


class ESPLoader(object):
    """ Base class providing access to ESP ROM & software stub bootloaders.
    Subclasses provide ESP8266 & ESP32 Family specific functionality.

    Don't instantiate this base class directly, either instantiate a subclass or
    call ESPLoader.detect_chip() which will interrogate the chip and return the
    appropriate subclass instance.

    """
    CHIP_NAME = "Espressif device"
    IS_STUB = False

    FPGA_SLOW_BOOT = False

    DEFAULT_PORT = "/dev/ttyUSB0"

    USES_RFC2217 = False

    # Commands supported by ESP8266 ROM bootloader
    ESP_FLASH_BEGIN = 0x02
    ESP_FLASH_DATA  = 0x03
    ESP_FLASH_END   = 0x04
    ESP_MEM_BEGIN   = 0x05
    ESP_MEM_END     = 0x06
    ESP_MEM_DATA    = 0x07
    ESP_SYNC        = 0x08
    ESP_WRITE_REG   = 0x09
    ESP_READ_REG    = 0x0a

    # Some comands supported by ESP32 and later chips ROM bootloader (or -8266 w/ stub)
    ESP_SPI_SET_PARAMS = 0x0B
    ESP_SPI_ATTACH     = 0x0D
    ESP_READ_FLASH_SLOW  = 0x0e  # ROM only, much slower than the stub flash read
    ESP_CHANGE_BAUDRATE = 0x0F
    ESP_FLASH_DEFL_BEGIN = 0x10
    ESP_FLASH_DEFL_DATA  = 0x11
    ESP_FLASH_DEFL_END   = 0x12
    ESP_SPI_FLASH_MD5    = 0x13

    # Commands supported by ESP32-S2 and later chips ROM bootloader only
    ESP_GET_SECURITY_INFO = 0x14

    # Some commands supported by stub only
    ESP_ERASE_FLASH = 0xD0
    ESP_ERASE_REGION = 0xD1
    ESP_READ_FLASH = 0xD2
    ESP_RUN_USER_CODE = 0xD3

    # Flash encryption encrypted data command
    ESP_FLASH_ENCRYPT_DATA = 0xD4

    # Response code(s) sent by ROM
    ROM_INVALID_RECV_MSG = 0x05   # response if an invalid message is received

    # Maximum block sized for RAM and Flash writes, respectively.
    ESP_RAM_BLOCK   = 0x1800

    FLASH_WRITE_SIZE = 0x400

    # Default baudrate. The ROM auto-bauds, so we can use more or less whatever we want.
    ESP_ROM_BAUD    = 115200

    # First byte of the application image
    ESP_IMAGE_MAGIC = 0xe9

    # Initial state for the checksum routine
    ESP_CHECKSUM_MAGIC = 0xef

    # Flash sector size, minimum unit of erase.
    FLASH_SECTOR_SIZE = 0x1000

    UART_DATE_REG_ADDR = 0x60000078

    CHIP_DETECT_MAGIC_REG_ADDR = 0x40001000  # This ROM address has a different value on each chip model

    UART_CLKDIV_MASK = 0xFFFFF

    # Memory addresses
    IROM_MAP_START = 0x40200000
    IROM_MAP_END = 0x40300000

    # The number of bytes in the UART response that signify command status
    STATUS_BYTES_LENGTH = 2

    # Response to ESP_SYNC might indicate that flasher stub is running instead of the ROM bootloader
    sync_stub_detected = False

    # Device PIDs
    USB_JTAG_SERIAL_PID = 0x1001

    # Chip IDs that are no longer supported by esptool
    UNSUPPORTED_CHIPS = {6: "ESP32-S3(beta 3)"}

    def __init__(self, port=DEFAULT_PORT, baud=ESP_ROM_BAUD, trace_enabled=False):
        """Base constructor for ESPLoader bootloader interaction

        Don't call this constructor, either instantiate ESP8266ROM
        or ESP32ROM, or use ESPLoader.detect_chip().

        This base class has all of the instance methods for bootloader
        functionality supported across various chips & stub
        loaders. Subclasses replace the functions they don't support
        with ones which throw NotImplementedInROMError().

        """
        self.secure_download_mode = False  # flag is set to True if esptool detects the ROM is in Secure Download Mode
        self.stub_is_disabled = False  # flag is set to True if esptool detects conditions which require the stub to be disabled

        if isinstance(port, basestring):
            self._port = serial.serial_for_url(port)
        else:
            self._port = port
        self._slip_reader = slip_reader(self._port, self.trace)
        # setting baud rate in a separate step is a workaround for
        # CH341 driver on some Linux versions (this opens at 9600 then
        # sets), shouldn't matter for other platforms/drivers. See
        # https://github.com/espressif/esptool/issues/44#issuecomment-107094446
        self._set_port_baudrate(baud)
        self._trace_enabled = trace_enabled
        # set write timeout, to prevent esptool blocked at write forever.
        try:
            self._port.write_timeout = DEFAULT_SERIAL_WRITE_TIMEOUT
        except NotImplementedError:
            # no write timeout for RFC2217 ports
            # need to set the property back to None or it will continue to fail
            self._port.write_timeout = None

    @property
    def serial_port(self):
        return self._port.port

    def _set_port_baudrate(self, baud):
        try:
            self._port.baudrate = baud
        except IOError:
            raise FatalError("Failed to set baud rate %d. The driver may not support this rate." % baud)

    @staticmethod
    def detect_chip(port=DEFAULT_PORT, baud=ESP_ROM_BAUD, connect_mode='default_reset', trace_enabled=False,
                    connect_attempts=DEFAULT_CONNECT_ATTEMPTS):
        """ Use serial access to detect the chip type.

        First, get_security_info command is sent to detect the ID of the chip
        (supported only by ESP32-C3 and later, works even in the Secure Download Mode).
        If this fails, we reconnect and fall-back to reading the magic number.
        It's mapped at a specific ROM address and has a different value on each chip model.
        This way we can use one memory read and compare it to the magic number for each chip type.

        This routine automatically performs ESPLoader.connect() (passing
        connect_mode parameter) as part of querying the chip.
        """
        inst = None
        detect_port = ESPLoader(port, baud, trace_enabled=trace_enabled)
        if detect_port.serial_port.startswith("rfc2217:"):
            detect_port.USES_RFC2217 = True
        detect_port.connect(connect_mode, connect_attempts, detecting=True)

        def check_if_stub(instance):
            print(f" {instance.CHIP_NAME}")
            if detect_port.sync_stub_detected:
                instance = instance.STUB_CLASS(instance)
                instance.sync_stub_detected = True
            return instance

        # First, check magic value to identify old chips (ESP8266, ESP32, ESP32-S2)
        print('Detecting chip type...', end='')
        try:
            chip_magic_value = detect_port.read_reg(ESPLoader.CHIP_DETECT_MAGIC_REG_ADDR)

            # Check if it's an old chip that doesn't support get_chip_id()
            for cls in [ESP8266ROM, ESP32ROM, ESP32S2ROM]:
                if chip_magic_value in cls.CHIP_DETECT_MAGIC_VALUE:
                    inst = cls(detect_port._port, baud, trace_enabled=trace_enabled)
                    inst = check_if_stub(inst)
                    inst._post_connect()
                    return inst

            # For newer chips, use get_chip_id() for accurate detection
            chip_id = detect_port.get_chip_id()

            # Create reverse mapping from IMAGE_CHIP_ID to chip name dynamically
            no_chip_id = ['esp8266', 'esp32', 'esp32s2']
            chip_map = {}
            for name in SUPPORTED_CHIPS:
                if name not in no_chip_id:
                    try:
                        cls = _chip_to_rom_loader(name)
                        if hasattr(cls, 'IMAGE_CHIP_ID'):
                            chip_map[cls.IMAGE_CHIP_ID] = name
                    except KeyError:
                        pass

            chip_name = chip_map.get(chip_id)
            if chip_name:
                cls = _chip_to_rom_loader(chip_name)
                inst = cls(detect_port._port, baud, trace_enabled=trace_enabled)
                inst = check_if_stub(inst)
                inst._post_connect()
                inst.check_chip_id()
                return inst

        except UnsupportedCommandError:
            raise FatalError("Unsupported Command Error received. Probably this means Secure Download Mode is enabled, "
                             "autodetection will not work. Need to manually specify the chip.")

        if inst is not None:
            return inst

        raise FatalError("Unexpected CHIP magic value 0x%08x. Failed to autodetect chip type." % (chip_magic_value))

    """ Read a SLIP packet from the serial port """
    def read(self):
        return next(self._slip_reader)

    """ Write bytes to the serial port while performing SLIP escaping """
    def write(self, packet):
        buf = b'\xc0' \
              + (packet.replace(b'\xdb', b'\xdb\xdd').replace(b'\xc0', b'\xdb\xdc')) \
              + b'\xc0'
        self.trace("Write %d bytes: %s", len(buf), HexFormatter(buf))
        self._port.write(buf)

    def trace(self, message, *format_args):
        if self._trace_enabled:
            now = time.time()
            try:

                delta = now - self._last_trace
            except AttributeError:
                delta = 0.0
            self._last_trace = now
            prefix = "TRACE +%.3f " % delta
            print(prefix + (message % format_args))

    """ Calculate checksum of a blob, as it is defined by the ROM """
    @staticmethod
    def checksum(data, state=ESP_CHECKSUM_MAGIC):
        for b in data:
            if type(b) is int:  # python 2/3 compat
                state ^= b
            else:
                state ^= ord(b)

        return state

    """ Send a request and read the response """
    def command(self, op=None, data=b"", chk=0, wait_response=True, timeout=DEFAULT_TIMEOUT):
        saved_timeout = self._port.timeout
        new_timeout = min(timeout, MAX_TIMEOUT)
        if new_timeout != saved_timeout:
            self._port.timeout = new_timeout

        try:
            if op is not None:
                self.trace("command op=0x%02x data len=%s wait_response=%d timeout=%.3f data=%s",
                           op, len(data), 1 if wait_response else 0, timeout, HexFormatter(data))
                pkt = struct.pack(b'<BBHI', 0x00, op, len(data), chk) + data
                self.write(pkt)

            if not wait_response:
                return

            # tries to get a response until that response has the
            # same operation as the request or a retries limit has
            # exceeded. This is needed for some esp8266s that
            # reply with more sync responses than expected.
            for retry in range(100):
                p = self.read()
                if len(p) < 8:
                    continue
                (resp, op_ret, len_ret, val) = struct.unpack('<BBHI', p[:8])
                if resp != 1:
                    continue
                data = p[8:]

                if op is None or op_ret == op:
                    return val, data
                if byte(data, 0) != 0 and byte(data, 1) == self.ROM_INVALID_RECV_MSG:
                    self.flush_input()  # Unsupported read_reg can result in more than one error response for some reason
                    raise UnsupportedCommandError(self, op)

        finally:
            if new_timeout != saved_timeout:
                self._port.timeout = saved_timeout

        raise FatalError("Response doesn't match request")

    def check_command(self, op_description, op=None, data=b'', chk=0, timeout=DEFAULT_TIMEOUT):
        """
        Execute a command with 'command', check the result code and throw an appropriate
        FatalError if it fails.

        Returns the "result" of a successful command.
        """
        val, data = self.command(op, data, chk, timeout=timeout)

        # things are a bit weird here, bear with us

        # the status bytes are the last 2/4 bytes in the data (depending on chip)
        if len(data) < self.STATUS_BYTES_LENGTH:
            raise FatalError("Failed to %s. Only got %d byte status response." % (op_description, len(data)))
        status_bytes = data[-self.STATUS_BYTES_LENGTH:]
        # we only care if the first one is non-zero. If it is, the second byte is a reason.
        if byte(status_bytes, 0) != 0:
            raise FatalError.WithResult('Failed to %s' % op_description, status_bytes)

        # if we had more data than just the status bytes, return it as the result
        # (this is used by the md5sum command, maybe other commands?)
        if len(data) > self.STATUS_BYTES_LENGTH:
            return data[:-self.STATUS_BYTES_LENGTH]
        else:  # otherwise, just return the 'val' field which comes from the reply header (this is used by read_reg)
            return val

    def flush_input(self):
        self._port.flushInput()
        self._slip_reader = slip_reader(self._port, self.trace)

    def sync(self):
        val, _ = self.command(self.ESP_SYNC, b'\x07\x07\x12\x20' + 32 * b'\x55',
                              timeout=SYNC_TIMEOUT)

        # ROM bootloaders send some non-zero "val" response. The flasher stub sends 0. If we receive 0 then it
        # probably indicates that the chip wasn't or couldn't be reseted properly and esptool is talking to the
        # flasher stub.
        self.sync_stub_detected = val == 0

        for _ in range(7):
            val, _ = self.command()
            self.sync_stub_detected &= val == 0

    def _setDTR(self, state):
        self._port.setDTR(state)

    def _setRTS(self, state):
        self._port.setRTS(state)
        # Work-around for adapters on Windows using the usbser.sys driver:
        # generate a dummy change to DTR so that the set-control-line-state
        # request is sent with the updated RTS state and the same DTR state
        self._port.setDTR(self._port.dtr)

    def _get_pid(self):
        if list_ports is None:
            print("\nListing all serial ports is currently not available. Can't get device PID.")
            return
        active_port = self._port.port

        # Pyserial only identifies regular ports, URL handlers are not supported
        if not active_port.lower().startswith(("com", "/dev/")):
            print("\nDevice PID identification is only supported on COM and /dev/ serial ports.")
            return
        # Return the real path if the active port is a symlink
        if active_port.startswith("/dev/") and os.path.islink(active_port):
            active_port = os.path.realpath(active_port)

        # The "cu" (call-up) device has to be used for outgoing communication on MacOS
        if sys.platform == "darwin" and "tty" in active_port:
            active_port = [active_port, active_port.replace("tty", "cu")]
        ports = list_ports.comports()
        for p in ports:
            if p.device in active_port:
                return p.pid
        print("\nFailed to get PID of a device on {}, using standard reset sequence.".format(active_port))

    def bootloader_reset(self, usb_jtag_serial=False, extra_delay=False):
        """ Issue a reset-to-bootloader, with USB-JTAG-Serial custom reset sequence option
        """
        # RTS = either CH_PD/EN or nRESET (both active low = chip in reset)
        # DTR = GPIO0 (active low = boot to flasher)
        #
        # DTR & RTS are active low signals,
        # ie True = pin @ 0V, False = pin @ VCC.
        if usb_jtag_serial:
            # Custom reset sequence, which is required when the device
            # is connecting via its USB-JTAG-Serial peripheral
            self._setRTS(False)
            self._setDTR(False)  # Idle
            time.sleep(0.1)
            self._setDTR(True)  # Set IO0
            self._setRTS(False)
            time.sleep(0.1)
            self._setRTS(True)  # Reset. Note dtr/rts calls inverted so we go through (1,1) instead of (0,0)
            self._setDTR(False)
            self._setRTS(True)  # Extra RTS set for RTS as Windows only propagates DTR on RTS setting
            time.sleep(0.1)
            self._setDTR(False)
            self._setRTS(False)
        else:
            # This fpga delay is for Espressif internal use
            fpga_delay = True if self.FPGA_SLOW_BOOT and os.environ.get("ESPTOOL_ENV_FPGA", "").strip() == "1" else False
            delay = 7 if fpga_delay else 0.5 if extra_delay else 0.05  # 0.5 needed for ESP32 rev0 and rev1

            self._setDTR(False)  # IO0=HIGH
            self._setRTS(True)   # EN=LOW, chip in reset
            time.sleep(0.1)
            self._setDTR(True)   # IO0=LOW
            self._setRTS(False)  # EN=HIGH, chip out of reset
            time.sleep(delay)
            self._setDTR(False)  # IO0=HIGH, done

    def _connect_attempt(self, mode='default_reset', usb_jtag_serial=False, extra_delay=False):
        """ A single connection attempt """
        last_error = None
        boot_log_detected = False
        download_mode = False

        # If we're doing no_sync, we're likely communicating as a pass through
        # with an intermediate device to the ESP32
        if mode == "no_reset_no_sync":
            return last_error

        if mode != 'no_reset':
            if not self.USES_RFC2217:  # Might block on rfc2217 ports
                self._port.reset_input_buffer()  # Empty serial buffer to isolate boot log
            self.bootloader_reset(usb_jtag_serial, extra_delay)

            # Detect the ROM boot log and check actual boot mode (ESP32 and later only)
            waiting = self._port.inWaiting()
            read_bytes = self._port.read(waiting)
            data = re.search(b'boot:(0x[0-9a-fA-F]+)(.*waiting for download)?', read_bytes, re.DOTALL)
            if data is not None:
                boot_log_detected = True
                boot_mode = data.group(1)
                download_mode = data.group(2) is not None

        for _ in range(5):
            try:
                self.flush_input()
                self._port.flushOutput()
                self.sync()
                return None
            except FatalError as e:
                print('.', end='')
                sys.stdout.flush()
                time.sleep(0.05)
                last_error = e

        if boot_log_detected:
            last_error = FatalError("Wrong boot mode detected ({})! The chip needs to be in download mode.".format(boot_mode.decode("utf-8")))
            if download_mode:
                last_error = FatalError("Download mode successfully detected, but getting no sync reply: The serial TX path seems to be down.")
        return last_error

    def get_memory_region(self, name):
        """ Returns a tuple of (start, end) for the memory map entry with the given name, or None if it doesn't exist
        """
        try:
            return [(start, end) for (start, end, n) in self.MEMORY_MAP if n == name][0]
        except IndexError:
            return None

    def connect(self, mode='default_reset', attempts=DEFAULT_CONNECT_ATTEMPTS, detecting=False, warnings=True):
        """ Try connecting repeatedly until successful, or giving up """
        if warnings and mode in ['no_reset', 'no_reset_no_sync']:
            print('WARNING: Pre-connection option "{}" was selected.'.format(mode),
                  'Connection may fail if the chip is not in bootloader or flasher stub mode.')
        print('Connecting...', end='')
        sys.stdout.flush()
        last_error = None

        usb_jtag_serial = (mode == 'usb_reset') or (self._get_pid() == self.USB_JTAG_SERIAL_PID)

        try:
            for _, extra_delay in zip(range(attempts) if attempts > 0 else itertools.count(), itertools.cycle((False, True))):
                last_error = self._connect_attempt(mode=mode, usb_jtag_serial=usb_jtag_serial, extra_delay=extra_delay)
                if last_error is None:
                    break
        finally:
            print('')  # end 'Connecting...' line

        if last_error is not None:
            raise FatalError('Failed to connect to {}: {}'
                             '\nFor troubleshooting steps visit: '
                             'https://docs.espressif.com/projects/esptool/en/latest/troubleshooting.html'.format(self.CHIP_NAME, last_error))

        if not detecting:
            try:
                # check the date code registers match what we expect to see
                chip_magic_value = self.read_reg(ESPLoader.CHIP_DETECT_MAGIC_REG_ADDR)
                if chip_magic_value not in self.CHIP_DETECT_MAGIC_VALUE:
                    actually = None
                    for cls in [ESP8266ROM, ESP32ROM, ESP32S2ROM, ESP32S3ROM, ESP32P4ROM,
                                ESP32C3ROM, ESP32H2ROM, ESP32C2ROM, ESP32C5ROM, ESP32C6ROM, ESP32C61ROM]:
                        if chip_magic_value in cls.CHIP_DETECT_MAGIC_VALUE:
                            actually = cls
                            break
                    if warnings and actually is None:
                        print(("WARNING: This chip doesn't appear to be a %s (chip magic value 0x%08x). "
                               "Probably it is unsupported by this version of esptool.") % (self.CHIP_NAME, chip_magic_value))
                    else:
                        raise FatalError("This chip is %s not %s. Wrong --chip argument?" % (actually.CHIP_NAME, self.CHIP_NAME))
            except UnsupportedCommandError:
                self.secure_download_mode = True
            self._post_connect()
            self.check_chip_id()

    def _post_connect(self):
        """
        Additional initialization hook, may be overridden by the chip-specific class.
        Gets called after connect, and after auto-detection.
        """
        pass

    def read_reg(self, addr, timeout=DEFAULT_TIMEOUT):
        """ Read memory address in target """
        # we don't call check_command here because read_reg() function is called
        # when detecting chip type, and the way we check for success (STATUS_BYTES_LENGTH) is different
        # for different chip types (!)
        val, data = self.command(self.ESP_READ_REG, struct.pack('<I', addr), timeout=timeout)
        if byte(data, 0) != 0:
            raise FatalError.WithResult("Failed to read register address %08x" % addr, data)
        return val

    """ Write to memory address in target """
    def write_reg(self, addr, value, mask=0xFFFFFFFF, delay_us=0, delay_after_us=0):
        command = struct.pack('<IIII', addr, value, mask, delay_us)
        if delay_after_us > 0:
            # add a dummy write to a date register as an excuse to have a delay
            command += struct.pack('<IIII', self.UART_DATE_REG_ADDR, 0, 0, delay_after_us)

        return self.check_command("write target memory", self.ESP_WRITE_REG, command)

    def update_reg(self, addr, mask, new_val):
        """ Update register at 'addr', replace the bits masked out by 'mask'
        with new_val. new_val is shifted left to match the LSB of 'mask'

        Returns just-written value of register.
        """
        shift = _mask_to_shift(mask)
        val = self.read_reg(addr)
        val &= ~mask
        val |= (new_val << shift) & mask
        self.write_reg(addr, val)

        return val

    """ Start downloading an application image to RAM """
    def mem_begin(self, size, blocks, blocksize, offset):
        if self.IS_STUB:  # check we're not going to overwrite a running stub with this data
            stub = self.STUB_CODE
            load_start = offset
            load_end = offset + size
            for (start, end) in [(stub["data_start"], stub["data_start"] + len(stub["data"])),
                                 (stub["text_start"], stub["text_start"] + len(stub["text"]))]:
                if load_start < end and load_end > start:
                    raise FatalError(("Software loader is resident at 0x%08x-0x%08x. "
                                      "Can't load binary at overlapping address range 0x%08x-0x%08x. "
                                      "Either change binary loading address, or use the --no-stub "
                                      "option to disable the software loader.") % (start, end, load_start, load_end))

        return self.check_command("enter RAM download mode", self.ESP_MEM_BEGIN,
                                  struct.pack('<IIII', size, blocks, blocksize, offset))

    """ Send a block of an image to RAM """
    def mem_block(self, data, seq):
        return self.check_command("write to target RAM", self.ESP_MEM_DATA,
                                  struct.pack('<IIII', len(data), seq, 0, 0) + data,
                                  self.checksum(data))

    """ Leave download mode and run the application """
    def mem_finish(self, entrypoint=0):
        # Sending ESP_MEM_END usually sends a correct response back, however sometimes
        # (with ROM loader) the executed code may reset the UART or change the baud rate
        # before the transmit FIFO is empty. So in these cases we set a short timeout and
        # ignore errors.
        timeout = DEFAULT_TIMEOUT if self.IS_STUB else MEM_END_ROM_TIMEOUT
        data = struct.pack('<II', int(entrypoint == 0), entrypoint)
        try:
            return self.check_command("leave RAM download mode", self.ESP_MEM_END,
                                      data=data, timeout=timeout)
        except FatalError:
            if self.IS_STUB:
                raise
            pass

    """ Start downloading to Flash (performs an erase)

    Returns number of blocks (of size self.FLASH_WRITE_SIZE) to write.
    """
    def flash_begin(self, size, offset, begin_rom_encrypted=False):
        num_blocks = (size + self.FLASH_WRITE_SIZE - 1) // self.FLASH_WRITE_SIZE
        erase_size = self.get_erase_size(offset, size)

        t = time.time()
        if self.IS_STUB:
            timeout = DEFAULT_TIMEOUT
        else:
            timeout = timeout_per_mb(ERASE_REGION_TIMEOUT_PER_MB, size)  # ROM performs the erase up front

        params = struct.pack('<IIII', erase_size, num_blocks, self.FLASH_WRITE_SIZE, offset)
        if isinstance(self, (ESP32S2ROM, ESP32S3ROM, ESP32C3ROM, ESP32C5ROM,
                             ESP32C6ROM, ESP32C61ROM, ESP32H2ROM, ESP32C2ROM, ESP32P4ROM)) and not self.IS_STUB:
            params += struct.pack('<I', 1 if begin_rom_encrypted else 0)
        self.check_command("enter Flash download mode", self.ESP_FLASH_BEGIN,
                           params, timeout=timeout)
        if size != 0 and not self.IS_STUB:
            print("Took %.2fs to erase flash block" % (time.time() - t))
        return num_blocks

    def flash_block(self, data, seq, timeout=DEFAULT_TIMEOUT):
        """Write block to flash, retry if fail"""
        for attempts_left in range(WRITE_BLOCK_ATTEMPTS - 1, -1, -1):
            try:
                self.check_command(
                    "write to target Flash after seq %d" % seq,
                    self.ESP_FLASH_DATA,
                    struct.pack("<IIII", len(data), seq, 0, 0) + data,
                    self.checksum(data),
                    timeout=timeout,
                )
                break
            except FatalError:
                if attempts_left:
                    self.trace(
                        "Block write failed, "
                        "retrying with {} attempts left".format(attempts_left)
                    )
                else:
                    raise

    def flash_encrypt_block(self, data, seq, timeout=DEFAULT_TIMEOUT):
        """Encrypt, write block to flash, retry if fail"""
        if isinstance(self, (ESP32S2ROM, ESP32S3ROM, ESP32C3ROM, ESP32C5ROM, ESP32C6ROM, ESP32C61ROM, ESP32H2ROM, ESP32C2ROM, ESP32P4ROM)) and not self.IS_STUB:
            # ROM support performs the encrypted writes via the normal write command,
            # triggered by flash_begin(begin_rom_encrypted=True)
            return self.flash_block(data, seq, timeout)

        for attempts_left in range(WRITE_BLOCK_ATTEMPTS - 1, -1, -1):
            try:
                self.check_command(
                    "Write encrypted to target Flash after seq %d" % seq,
                    self.ESP_FLASH_ENCRYPT_DATA,
                    struct.pack("<IIII", len(data), seq, 0, 0) + data,
                    self.checksum(data),
                    timeout=timeout,
                )
                break
            except FatalError:
                if attempts_left:
                    self.trace(
                        "Encrypted block write failed, "
                        "retrying with {} attempts left".format(attempts_left)
                    )
                else:
                    raise

    """ Leave flash mode and run/reboot """
    def flash_finish(self, reboot=False):
        pkt = struct.pack('<I', int(not reboot))
        # stub sends a reply to this command
        self.check_command("leave Flash mode", self.ESP_FLASH_END, pkt)

    """ Run application code in flash """
    def run(self, reboot=False):
        # Fake flash begin immediately followed by flash end
        self.flash_begin(0, 0)
        self.flash_finish(reboot)

    """ Read SPI flash manufacturer and device id """
    def flash_id(self):
        SPIFLASH_RDID = 0x9F
        return self.run_spiflash_command(SPIFLASH_RDID, b"", 24)

    def get_security_info(self):
        res = self.check_command('get security info', self.ESP_GET_SECURITY_INFO, b'')
        esp32s2 = True if len(res) == 12 else False
        res = struct.unpack("<IBBBBBBBB" if esp32s2 else "<IBBBBBBBBII", res)
        return {
            "flags": res[0],
            "flash_crypt_cnt": res[1],
            "key_purposes": res[2:9],
            "chip_id": None if esp32s2 else res[9],
            "api_version": None if esp32s2 else res[10],
        }

    def get_chip_id(self):
        """Get chip ID using ESP_GET_SECURITY_INFO command.
        Supported by ESP32-C3 and later chips (including ESP32-C5, ESP32-C6, ESP32-C61, etc.)
        NOTE: This function should only be called after verifying the chip is NOT ESP8266/ESP32/ESP32-S2
        to avoid breaking the stub loader.
        """
        res = self.check_command('get security info', self.ESP_GET_SECURITY_INFO, b'')
        res = struct.unpack("<IBBBBBBBBI", res[:16])  # 4b flags, 1b flash_crypt_cnt, 7*1b key_purposes, 4b chip_id
        chip_id = res[9]  # 2/4 status bytes invariant
        return chip_id

    @classmethod
    def parse_flash_size_arg(cls, arg):
        try:
            return cls.FLASH_SIZES[arg]
        except KeyError:
            raise FatalError("Flash size '%s' is not supported by this chip type. Supported sizes: %s"
                             % (arg, ", ".join(cls.FLASH_SIZES.keys())))

    @classmethod
    def parse_flash_freq_arg(cls, arg):
        try:
            return cls.FLASH_FREQUENCY[arg]
        except KeyError:
            raise FatalError("Flash frequency '%s' is not supported by this chip type. Supported frequencies: %s"
                             % (arg, ", ".join(cls.FLASH_FREQUENCY.keys())))

    def run_stub(self, stub=None):
        if stub is None:
            stub = self.STUB_CODE

        if self.sync_stub_detected:
            print("Stub is already running. No upload is necessary.")
            return self.STUB_CLASS(self)

        # Upload
        print("Uploading stub...")
        for field in ['text', 'data']:
            if field in stub:
                offs = stub[field + "_start"]
                length = len(stub[field])
                blocks = (length + self.ESP_RAM_BLOCK - 1) // self.ESP_RAM_BLOCK
                self.mem_begin(length, blocks, self.ESP_RAM_BLOCK, offs)
                for seq in range(blocks):
                    from_offs = seq * self.ESP_RAM_BLOCK
                    to_offs = from_offs + self.ESP_RAM_BLOCK
                    self.mem_block(stub[field][from_offs:to_offs], seq)
        print("Running stub...")
        self.mem_finish(stub['entry'])

        p = self.read()
        if p != b'OHAI':
            raise FatalError("Failed to start stub. Unexpected response: %s" % p)
        print("Stub running...")
        return self.STUB_CLASS(self)

    @stub_and_esp32_function_only
    def flash_defl_begin(self, size, compsize, offset):
        """ Start downloading compressed data to Flash (performs an erase)

        Returns number of blocks (size self.FLASH_WRITE_SIZE) to write.
        """
        num_blocks = (compsize + self.FLASH_WRITE_SIZE - 1) // self.FLASH_WRITE_SIZE
        erase_blocks = (size + self.FLASH_WRITE_SIZE - 1) // self.FLASH_WRITE_SIZE

        t = time.time()
        if self.IS_STUB:
            write_size = size  # stub expects number of bytes here, manages erasing internally
            timeout = DEFAULT_TIMEOUT
        else:
            write_size = erase_blocks * self.FLASH_WRITE_SIZE  # ROM expects rounded up to erase block size
            timeout = timeout_per_mb(ERASE_REGION_TIMEOUT_PER_MB, write_size)  # ROM performs the erase up front
        print("Compressed %d bytes to %d..." % (size, compsize))
        params = struct.pack('<IIII', write_size, num_blocks, self.FLASH_WRITE_SIZE, offset)
        if isinstance(self, (ESP32S2ROM, ESP32S3ROM, ESP32C3ROM,ESP32C5ROM,
                             ESP32C6ROM, ESP32C61ROM, ESP32H2ROM, ESP32C2ROM, ESP32P4ROM)) and not self.IS_STUB:
            params += struct.pack('<I', 0)  # extra param is to enter encrypted flash mode via ROM (not supported currently)
        self.check_command("enter compressed flash mode", self.ESP_FLASH_DEFL_BEGIN, params, timeout=timeout)
        if size != 0 and not self.IS_STUB:
            # (stub erases as it writes, but ROM loaders erase on begin)
            print("Took %.2fs to erase flash block" % (time.time() - t))
        return num_blocks

    @stub_and_esp32_function_only
    def flash_defl_block(self, data, seq, timeout=DEFAULT_TIMEOUT):
        """Write block to flash, send compressed, retry if fail"""
        for attempts_left in range(WRITE_BLOCK_ATTEMPTS - 1, -1, -1):
            try:
                self.check_command(
                    "write compressed data to flash after seq %d" % seq,
                    self.ESP_FLASH_DEFL_DATA,
                    struct.pack("<IIII", len(data), seq, 0, 0) + data,
                    self.checksum(data),
                    timeout=timeout,
                )
                break
            except FatalError:
                if attempts_left:
                    self.trace(
                        "Compressed block write failed, "
                        "retrying with {} attempts left".format(attempts_left)
                    )
                else:
                    raise

    """ Leave compressed flash mode and run/reboot """
    @stub_and_esp32_function_only
    def flash_defl_finish(self, reboot=False):
        if not reboot and not self.IS_STUB:
            # skip sending flash_finish to ROM loader, as this
            # exits the bootloader. Stub doesn't do this.
            return
        pkt = struct.pack('<I', int(not reboot))
        self.check_command("leave compressed flash mode", self.ESP_FLASH_DEFL_END, pkt)
        self.in_bootloader = False

    @stub_and_esp32_function_only
    def flash_md5sum(self, addr, size):
        # the MD5 command returns additional bytes in the standard
        # command reply slot
        timeout = timeout_per_mb(MD5_TIMEOUT_PER_MB, size)
        res = self.check_command('calculate md5sum', self.ESP_SPI_FLASH_MD5, struct.pack('<IIII', addr, size, 0, 0),
                                 timeout=timeout)

        if len(res) == 32:
            return res.decode("utf-8")  # already hex formatted
        elif len(res) == 16:
            return hexify(res).lower()
        else:
            raise FatalError("MD5Sum command returned unexpected result: %r" % res)

    @stub_and_esp32_function_only
    def change_baud(self, baud):
        print("Changing baud rate to %d" % baud)
        # stub takes the new baud rate and the old one
        second_arg = self._port.baudrate if self.IS_STUB else 0
        self.command(self.ESP_CHANGE_BAUDRATE, struct.pack('<II', baud, second_arg))
        print("Changed.")
        self._set_port_baudrate(baud)
        time.sleep(0.05)  # get rid of crap sent during baud rate change
        self.flush_input()

    @stub_function_only
    def erase_flash(self):
        # depending on flash chip model the erase may take this long (maybe longer!)
        self.check_command("erase flash", self.ESP_ERASE_FLASH,
                           timeout=CHIP_ERASE_TIMEOUT)

    @stub_function_only
    def erase_region(self, offset, size):
        if offset % self.FLASH_SECTOR_SIZE != 0:
            raise FatalError("Offset to erase from must be a multiple of 4096")
        if size % self.FLASH_SECTOR_SIZE != 0:
            raise FatalError("Size of data to erase must be a multiple of 4096")
        timeout = timeout_per_mb(ERASE_REGION_TIMEOUT_PER_MB, size)
        self.check_command("erase region", self.ESP_ERASE_REGION, struct.pack('<II', offset, size), timeout=timeout)

    def read_flash_slow(self, offset, length, progress_fn):
        raise NotImplementedInROMError(self, self.read_flash_slow)

    def read_flash(self, offset, length, progress_fn=None):
        if not self.IS_STUB:
            return self.read_flash_slow(offset, length, progress_fn)  # ROM-only routine

        # issue a standard bootloader command to trigger the read
        self.check_command("read flash", self.ESP_READ_FLASH,
                           struct.pack('<IIII',
                                       offset,
                                       length,
                                       self.FLASH_SECTOR_SIZE,
                                       64))
        # now we expect (length // block_size) SLIP frames with the data
        data = b''
        while len(data) < length:
            p = self.read()
            data += p
            if len(data) < length and len(p) < self.FLASH_SECTOR_SIZE:
                raise FatalError('Corrupt data, expected 0x%x bytes but received 0x%x bytes' % (self.FLASH_SECTOR_SIZE, len(p)))
            self.write(struct.pack('<I', len(data)))
            if progress_fn and (len(data) % 1024 == 0 or len(data) == length):
                progress_fn(len(data), length)
        if progress_fn:
            progress_fn(len(data), length)
        if len(data) > length:
            raise FatalError('Read more than expected')

        digest_frame = self.read()
        if len(digest_frame) != 16:
            raise FatalError('Expected digest, got: %s' % hexify(digest_frame))
        expected_digest = hexify(digest_frame).upper()
        digest = hashlib.md5(data).hexdigest().upper()
        if digest != expected_digest:
            raise FatalError('Digest mismatch: expected %s, got %s' % (expected_digest, digest))
        return data

    def flash_spi_attach(self, hspi_arg):
        """Send SPI attach command to enable the SPI flash pins

        ESP8266 ROM does this when you send flash_begin, ESP32 ROM
        has it as a SPI command.
        """
        # last 3 bytes in ESP_SPI_ATTACH argument are reserved values
        arg = struct.pack('<I', hspi_arg)
        if not self.IS_STUB:
            # ESP32 ROM loader takes additional 'is legacy' arg, which is not
            # currently supported in the stub loader or esptool.py (as it's not usually needed.)
            is_legacy = 0
            arg += struct.pack('BBBB', is_legacy, 0, 0, 0)
        self.check_command("configure SPI flash pins", ESP32ROM.ESP_SPI_ATTACH, arg)

    def flash_set_parameters(self, size):
        """Tell the ESP bootloader the parameters of the chip

        Corresponds to the "flashchip" data structure that the ROM
        has in RAM.

        'size' is in bytes.

        All other flash parameters are currently hardcoded (on ESP8266
        these are mostly ignored by ROM code, on ESP32 I'm not sure.)
        """
        fl_id = 0
        total_size = size
        block_size = 64 * 1024
        sector_size = 4 * 1024
        page_size = 256
        status_mask = 0xffff
        self.check_command("set SPI params", ESP32ROM.ESP_SPI_SET_PARAMS,
                           struct.pack('<IIIIII', fl_id, total_size, block_size, sector_size, page_size, status_mask))

    def run_spiflash_command(self, spiflash_command, data=b"", read_bits=0, addr=None, addr_len=0, dummy_len=0):
        """Run an arbitrary SPI flash command.

        This function uses the "USR_COMMAND" functionality in the ESP
        SPI hardware, rather than the precanned commands supported by
        hardware. So the value of spiflash_command is an actual command
        byte, sent over the wire.

        After writing command byte, writes 'data' to MOSI and then
        reads back 'read_bits' of reply on MISO. Result is a number.
        """

        # SPI_USR register flags
        SPI_USR_COMMAND = (1 << 31)
        SPI_USR_ADDR    = (1 << 30)
        SPI_USR_DUMMY   = (1 << 29)
        SPI_USR_MISO    = (1 << 28)
        SPI_USR_MOSI    = (1 << 27)

        # SPI registers, base address differs ESP32* vs 8266
        base = self.SPI_REG_BASE
        SPI_CMD_REG       = base + 0x00
        SPI_ADDR_REG      = base + 0x04
        SPI_USR_REG       = base + self.SPI_USR_OFFS
        SPI_USR1_REG      = base + self.SPI_USR1_OFFS
        SPI_USR2_REG      = base + self.SPI_USR2_OFFS
        SPI_W0_REG        = base + self.SPI_W0_OFFS

        # following two registers are ESP32 and later chips only
        if self.SPI_MOSI_DLEN_OFFS is not None:
            # ESP32 and later chips have a more sophisticated way to set up "user" commands
            def set_data_lengths(mosi_bits, miso_bits):
                SPI_MOSI_DLEN_REG = base + self.SPI_MOSI_DLEN_OFFS
                SPI_MISO_DLEN_REG = base + self.SPI_MISO_DLEN_OFFS
                if mosi_bits > 0:
                    self.write_reg(SPI_MOSI_DLEN_REG, mosi_bits - 1)
                if miso_bits > 0:
                    self.write_reg(SPI_MISO_DLEN_REG, miso_bits - 1)
                flags = 0
                if dummy_len > 0:
                    flags |= (dummy_len - 1)
                if addr_len > 0:
                    flags |= (addr_len - 1) << SPI_USR_ADDR_LEN_SHIFT
                if flags:
                    self.write_reg(SPI_USR1_REG, flags)
        else:
            def set_data_lengths(mosi_bits, miso_bits):
                SPI_DATA_LEN_REG = SPI_USR1_REG
                SPI_MOSI_BITLEN_S = 17
                SPI_MISO_BITLEN_S = 8
                mosi_mask = 0 if (mosi_bits == 0) else (mosi_bits - 1)
                miso_mask = 0 if (miso_bits == 0) else (miso_bits - 1)
                flags = (miso_mask << SPI_MISO_BITLEN_S) | (mosi_mask << SPI_MOSI_BITLEN_S)
                if dummy_len > 0:
                    flags |= (dummy_len - 1)
                if addr_len > 0:
                    flags |= (addr_len - 1) << SPI_USR_ADDR_LEN_SHIFT
                self.write_reg(SPI_DATA_LEN_REG, flags)

        # SPI peripheral "command" bitmasks for SPI_CMD_REG
        SPI_CMD_USR  = (1 << 18)

        # shift values
        SPI_USR2_COMMAND_LEN_SHIFT = 28
        SPI_USR_ADDR_LEN_SHIFT = 26

        if read_bits > 32:
            raise FatalError("Reading more than 32 bits back from a SPI flash operation is unsupported")
        if len(data) > 64:
            raise FatalError("Writing more than 64 bytes of data with one SPI command is unsupported")

        data_bits = len(data) * 8
        old_spi_usr = self.read_reg(SPI_USR_REG)
        old_spi_usr2 = self.read_reg(SPI_USR2_REG)
        flags = SPI_USR_COMMAND
        if read_bits > 0:
            flags |= SPI_USR_MISO
        if data_bits > 0:
            flags |= SPI_USR_MOSI
        if addr_len > 0:
            flags |= SPI_USR_ADDR
        if dummy_len > 0:
            flags |= SPI_USR_DUMMY
        set_data_lengths(data_bits, read_bits)
        self.write_reg(SPI_USR_REG, flags)
        self.write_reg(SPI_USR2_REG,
                       (7 << SPI_USR2_COMMAND_LEN_SHIFT) | spiflash_command)
        if addr and addr_len > 0:
            self.write_reg(SPI_ADDR_REG, addr)
        if data_bits == 0:
            self.write_reg(SPI_W0_REG, 0)  # clear data register before we read it
        else:
            data = pad_to(data, 4, b'\00')  # pad to 32-bit multiple
            words = struct.unpack("I" * (len(data) // 4), data)
            next_reg = SPI_W0_REG
            for word in words:
                self.write_reg(next_reg, word)
                next_reg += 4
        self.write_reg(SPI_CMD_REG, SPI_CMD_USR)

        def wait_done():
            for _ in range(10):
                if (self.read_reg(SPI_CMD_REG) & SPI_CMD_USR) == 0:
                    return
            raise FatalError("SPI command did not complete in time")
        wait_done()

        status = self.read_reg(SPI_W0_REG)
        # restore some SPI controller registers
        self.write_reg(SPI_USR_REG, old_spi_usr)
        self.write_reg(SPI_USR2_REG, old_spi_usr2)
        return status

    def read_spiflash_sfdp(self, addr, read_bits):
        CMD_RDSFDP = 0x5A
        return self.run_spiflash_command(CMD_RDSFDP, read_bits=read_bits, addr=addr, addr_len=24, dummy_len=8)

    def read_status(self, num_bytes=2):
        """Read up to 24 bits (num_bytes) of SPI flash status register contents
        via RDSR, RDSR2, RDSR3 commands

        Not all SPI flash supports all three commands. The upper 1 or 2
        bytes may be 0xFF.
        """
        SPIFLASH_RDSR  = 0x05
        SPIFLASH_RDSR2 = 0x35
        SPIFLASH_RDSR3 = 0x15

        status = 0
        shift = 0
        for cmd in [SPIFLASH_RDSR, SPIFLASH_RDSR2, SPIFLASH_RDSR3][0:num_bytes]:
            status += self.run_spiflash_command(cmd, read_bits=8) << shift
            shift += 8
        return status

    def write_status(self, new_status, num_bytes=2, set_non_volatile=False):
        """Write up to 24 bits (num_bytes) of new status register

        num_bytes can be 1, 2 or 3.

        Not all flash supports the additional commands to write the
        second and third byte of the status register. When writing 2
        bytes, esptool also sends a 16-byte WRSR command (as some
        flash types use this instead of WRSR2.)

        If the set_non_volatile flag is set, non-volatile bits will
        be set as well as volatile ones (WREN used instead of WEVSR).

        """
        SPIFLASH_WRSR = 0x01
        SPIFLASH_WRSR2 = 0x31
        SPIFLASH_WRSR3 = 0x11
        SPIFLASH_WEVSR = 0x50
        SPIFLASH_WREN = 0x06
        SPIFLASH_WRDI = 0x04

        enable_cmd = SPIFLASH_WREN if set_non_volatile else SPIFLASH_WEVSR

        # try using a 16-bit WRSR (not supported by all chips)
        # this may be redundant, but shouldn't hurt
        if num_bytes == 2:
            self.run_spiflash_command(enable_cmd)
            self.run_spiflash_command(SPIFLASH_WRSR, struct.pack("<H", new_status))

        # also try using individual commands (also not supported by all chips for num_bytes 2 & 3)
        for cmd in [SPIFLASH_WRSR, SPIFLASH_WRSR2, SPIFLASH_WRSR3][0:num_bytes]:
            self.run_spiflash_command(enable_cmd)
            self.run_spiflash_command(cmd, struct.pack("B", new_status & 0xFF))
            new_status >>= 8

        self.run_spiflash_command(SPIFLASH_WRDI)

    def get_crystal_freq(self):
        # Figure out the crystal frequency from the UART clock divider
        # Returns a normalized value in integer MHz (40 or 26 are the only supported values)
        #
        # The logic here is:
        # - We know that our baud rate and the ESP UART baud rate are roughly the same, or we couldn't communicate
        # - We can read the UART clock divider register to know how the ESP derives this from the APB bus frequency
        # - Multiplying these two together gives us the bus frequency which is either the crystal frequency (ESP32)
        #   or double the crystal frequency (ESP8266). See the self.XTAL_CLK_DIVIDER parameter for this factor.
        uart_div = self.read_reg(self.UART_CLKDIV_REG) & self.UART_CLKDIV_MASK
        est_xtal = (self._port.baudrate * uart_div) / 1e6 / self.XTAL_CLK_DIVIDER
        norm_xtal = 40 if est_xtal > 33 else 26
        if abs(norm_xtal - est_xtal) > 1:
            print("WARNING: Detected crystal freq %.2fMHz is quite different to normalized freq %dMHz. Unsupported crystal in use?" % (est_xtal, norm_xtal))
        return norm_xtal

    def hard_reset(self):
        print('Hard resetting via RTS pin...')
        self._setRTS(True)  # EN->LOW
        time.sleep(0.1)
        self._setRTS(False)

    def soft_reset(self, stay_in_bootloader):
        if not self.IS_STUB:
            if stay_in_bootloader:
                return  # ROM bootloader is already in bootloader!
            else:
                # 'run user code' is as close to a soft reset as we can do
                self.flash_begin(0, 0)
                self.flash_finish(False)
        else:
            if stay_in_bootloader:
                # soft resetting from the stub loader
                # will re-load the ROM bootloader
                self.flash_begin(0, 0)
                self.flash_finish(True)
            elif self.CHIP_NAME != "ESP8266":
                raise FatalError("Soft resetting is currently only supported on ESP8266")
            else:
                # running user code from stub loader requires some hacks
                # in the stub loader
                self.command(self.ESP_RUN_USER_CODE, wait_response=False)

    def check_chip_id(self):
        try:
            chip_id = self.get_chip_id()
            if chip_id != self.IMAGE_CHIP_ID:
                print("WARNING: Chip ID {} ({}) doesn't match expected Chip ID {}. esptool may not work correctly."
                      .format(chip_id, self.UNSUPPORTED_CHIPS.get(chip_id, 'Unknown'), self.IMAGE_CHIP_ID))
                # Try to flash anyways by disabling stub
                self.stub_is_disabled = True
        except (NotImplementedInROMError, UnsupportedCommandError):
            # get_chip_id() not supported by this chip (ESP8266, ESP32, ESP32-S2)
            pass


class ESP8266ROM(ESPLoader):
    """ Access class for ESP8266 ROM bootloader
    """
    CHIP_NAME = "ESP8266"
    IS_STUB = False
    IMAGE_CHIP_ID = 0

    CHIP_DETECT_MAGIC_VALUE = [0xfff0c101]

    # OTP ROM addresses
    ESP_OTP_MAC0    = 0x3ff00050
    ESP_OTP_MAC1    = 0x3ff00054
    ESP_OTP_MAC3    = 0x3ff0005c

    SPI_REG_BASE    = 0x60000200
    SPI_USR_OFFS    = 0x1c
    SPI_USR1_OFFS   = 0x20
    SPI_USR2_OFFS   = 0x24
    SPI_MOSI_DLEN_OFFS = None
    SPI_MISO_DLEN_OFFS = None
    SPI_W0_OFFS     = 0x40

    UART_CLKDIV_REG = 0x60000014

    XTAL_CLK_DIVIDER = 2

    FLASH_SIZES = {
        '512KB': 0x00,
        '256KB': 0x10,
        '1MB': 0x20,
        '2MB': 0x30,
        '4MB': 0x40,
        '2MB-c1': 0x50,
        '4MB-c1': 0x60,
        '8MB': 0x80,
        '16MB': 0x90,
    }

    FLASH_FREQUENCY = {
        '80m': 0xf,
        '40m': 0x0,
        '26m': 0x1,
        '20m': 0x2,
    }

    BOOTLOADER_FLASH_OFFSET = 0

    MEMORY_MAP = [[0x3FF00000, 0x3FF00010, "DPORT"],
                  [0x3FFE8000, 0x40000000, "DRAM"],
                  [0x40100000, 0x40108000, "IRAM"],
                  [0x40201010, 0x402E1010, "IROM"]]

    def get_efuses(self):
        # Return the 128 bits of ESP8266 efuse as a single Python integer
        result = self.read_reg(0x3ff0005c) << 96
        result |= self.read_reg(0x3ff00058) << 64
        result |= self.read_reg(0x3ff00054) << 32
        result |= self.read_reg(0x3ff00050)
        return result

    def _get_flash_size(self, efuses):
        # rX_Y = EFUSE_DATA_OUTX[Y]
        r0_4 = (efuses & (1 << 4)) != 0
        r3_25 = (efuses & (1 << 121)) != 0
        r3_26 = (efuses & (1 << 122)) != 0
        r3_27 = (efuses & (1 << 123)) != 0

        if r0_4 and not r3_25:
            if not r3_27 and not r3_26:
                return 1
            elif not r3_27 and r3_26:
                return 2
        if not r0_4 and r3_25:
            if not r3_27 and not r3_26:
                return 2
            elif not r3_27 and r3_26:
                return 4
        return -1

    def get_chip_description(self):
        efuses = self.get_efuses()
        is_8285 = (efuses & ((1 << 4) | 1 << 80)) != 0  # One or the other efuse bit is set for ESP8285
        if is_8285:
            flash_size = self._get_flash_size(efuses)
            max_temp = (efuses & (1 << 5)) != 0  # This efuse bit identifies the max flash temperature
            chip_name = {
                1: "ESP8285H08" if max_temp else "ESP8285N08",
                2: "ESP8285H16" if max_temp else "ESP8285N16"
            }.get(flash_size, "ESP8285")
            return chip_name
        return "ESP8266EX"

    def get_chip_features(self):
        features = ["WiFi"]
        if "ESP8285" in self.get_chip_description():
            features += ["Embedded Flash"]
        return features

    def flash_spi_attach(self, hspi_arg):
        if self.IS_STUB:
            super(ESP8266ROM, self).flash_spi_attach(hspi_arg)
        else:
            # ESP8266 ROM has no flash_spi_attach command in serial protocol,
            # but flash_begin will do it
            self.flash_begin(0, 0)

    def flash_set_parameters(self, size):
        # not implemented in ROM, but OK to silently skip for ROM
        if self.IS_STUB:
            super(ESP8266ROM, self).flash_set_parameters(size)

    def chip_id(self):
        """ Read Chip ID from efuse - the equivalent of the SDK system_get_chip_id() function """
        id0 = self.read_reg(self.ESP_OTP_MAC0)
        id1 = self.read_reg(self.ESP_OTP_MAC1)
        return (id0 >> 24) | ((id1 & MAX_UINT24) << 8)

    def read_mac(self):
        """ Read MAC from OTP ROM """
        mac0 = self.read_reg(self.ESP_OTP_MAC0)
        mac1 = self.read_reg(self.ESP_OTP_MAC1)
        mac3 = self.read_reg(self.ESP_OTP_MAC3)
        if (mac3 != 0):
            oui = ((mac3 >> 16) & 0xff, (mac3 >> 8) & 0xff, mac3 & 0xff)
        elif ((mac1 >> 16) & 0xff) == 0:
            oui = (0x18, 0xfe, 0x34)
        elif ((mac1 >> 16) & 0xff) == 1:
            oui = (0xac, 0xd0, 0x74)
        else:
            raise FatalError("Unknown OUI")
        return oui + ((mac1 >> 8) & 0xff, mac1 & 0xff, (mac0 >> 24) & 0xff)

    def get_erase_size(self, offset, size):
        """ Calculate an erase size given a specific size in bytes.

        Provides a workaround for the bootloader erase bug."""

        sectors_per_block = 16
        sector_size = self.FLASH_SECTOR_SIZE
        num_sectors = (size + sector_size - 1) // sector_size
        start_sector = offset // sector_size

        head_sectors = sectors_per_block - (start_sector % sectors_per_block)
        if num_sectors < head_sectors:
            head_sectors = num_sectors

        if num_sectors < 2 * head_sectors:
            return (num_sectors + 1) // 2 * sector_size
        else:
            return (num_sectors - head_sectors) * sector_size

    def override_vddsdio(self, new_voltage):
        raise NotImplementedInROMError("Overriding VDDSDIO setting only applies to ESP32")


class ESP8266StubLoader(ESP8266ROM):
    """ Access class for ESP8266 stub loader, runs on top of ROM.
    """
    FLASH_WRITE_SIZE = 0x4000  # matches MAX_WRITE_BLOCK in stub_loader.c
    IS_STUB = True

    def __init__(self, rom_loader):
        self.secure_download_mode = rom_loader.secure_download_mode
        self._port = rom_loader._port
        self._trace_enabled = rom_loader._trace_enabled
        self.flush_input()  # resets _slip_reader

    def get_erase_size(self, offset, size):
        return size  # stub doesn't have same size bug as ROM loader


ESP8266ROM.STUB_CLASS = ESP8266StubLoader


class ESP32ROM(ESPLoader):
    """Access class for ESP32 ROM bootloader

    """
    CHIP_NAME = "ESP32"
    IMAGE_CHIP_ID = 0
    IS_STUB = False

    FPGA_SLOW_BOOT = True

    CHIP_DETECT_MAGIC_VALUE = [0x00f01d83]

    IROM_MAP_START = 0x400d0000
    IROM_MAP_END   = 0x40400000

    DROM_MAP_START = 0x3F400000
    DROM_MAP_END   = 0x3F800000

    # ESP32 uses a 4 byte status reply
    STATUS_BYTES_LENGTH = 4

    SPI_REG_BASE   = 0x3ff42000
    SPI_USR_OFFS    = 0x1c
    SPI_USR1_OFFS   = 0x20
    SPI_USR2_OFFS   = 0x24
    SPI_MOSI_DLEN_OFFS = 0x28
    SPI_MISO_DLEN_OFFS = 0x2c
    EFUSE_RD_REG_BASE = 0x3ff5a000

    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT_REG = EFUSE_RD_REG_BASE + 0x18
    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT = (1 << 7)  # EFUSE_RD_DISABLE_DL_ENCRYPT

    DR_REG_SYSCON_BASE = 0x3ff66000
    APB_CTL_DATE_ADDR = DR_REG_SYSCON_BASE + 0x7C
    APB_CTL_DATE_V = 0x1
    APB_CTL_DATE_S = 31

    SPI_W0_OFFS = 0x80

    UART_CLKDIV_REG = 0x3ff40014

    XTAL_CLK_DIVIDER = 1

    FLASH_SIZES = {
        '1MB': 0x00,
        '2MB': 0x10,
        '4MB': 0x20,
        '8MB': 0x30,
        '16MB': 0x40,
        '32MB': 0x50,
        '64MB': 0x60,
        '128MB': 0x70
    }

    FLASH_FREQUENCY = {
        '80m': 0xf,
        '40m': 0x0,
        '26m': 0x1,
        '20m': 0x2,
    }

    BOOTLOADER_FLASH_OFFSET = 0x1000

    OVERRIDE_VDDSDIO_CHOICES = ["1.8V", "1.9V", "OFF"]

    MEMORY_MAP = [[0x00000000, 0x00010000, "PADDING"],
                  [0x3F400000, 0x3F800000, "DROM"],
                  [0x3F800000, 0x3FC00000, "EXTRAM_DATA"],
                  [0x3FF80000, 0x3FF82000, "RTC_DRAM"],
                  [0x3FF90000, 0x40000000, "BYTE_ACCESSIBLE"],
                  [0x3FFAE000, 0x40000000, "DRAM"],
                  [0x3FFE0000, 0x3FFFFFFC, "DIRAM_DRAM"],
                  [0x40000000, 0x40070000, "IROM"],
                  [0x40070000, 0x40078000, "CACHE_PRO"],
                  [0x40078000, 0x40080000, "CACHE_APP"],
                  [0x40080000, 0x400A0000, "IRAM"],
                  [0x400A0000, 0x400BFFFC, "DIRAM_IRAM"],
                  [0x400C0000, 0x400C2000, "RTC_IRAM"],
                  [0x400D0000, 0x40400000, "IROM"],
                  [0x50000000, 0x50002000, "RTC_DATA"]]

    FLASH_ENCRYPTED_WRITE_ALIGN = 32

    """ Try to read the BLOCK1 (encryption key) and check if it is valid """

    def is_flash_encryption_key_valid(self):

        """ Bit 0 of efuse_rd_disable[3:0] is mapped to BLOCK1
        this bit is at position 16 in EFUSE_BLK0_RDATA0_REG """
        word0 = self.read_efuse(0)
        rd_disable = (word0 >> 16) & 0x1

        # reading of BLOCK1 is NOT ALLOWED so we assume valid key is programmed
        if rd_disable:
            return True
        else:
            # reading of BLOCK1 is ALLOWED so we will read and verify for non-zero.
            # When ESP32 has not generated AES/encryption key in BLOCK1, the contents will be readable and 0.
            # If the flash encryption is enabled it is expected to have a valid non-zero key. We break out on
            # first occurance of non-zero value
            key_word = [0] * 7
            for i in range(len(key_word)):
                key_word[i] = self.read_efuse(14 + i)
                # key is non-zero so break & return
                if key_word[i] != 0:
                    return True
            return False

    def get_flash_crypt_config(self):
        """ For flash encryption related commands we need to make sure
        user has programmed all the relevant efuse correctly so before
        writing encrypted write_flash_encrypt esptool will verify the values
        of flash_crypt_config to be non zero if they are not read
        protected. If the values are zero a warning will be printed

        bit 3 in efuse_rd_disable[3:0] is mapped to flash_crypt_config
        this bit is at position 19 in EFUSE_BLK0_RDATA0_REG """
        word0 = self.read_efuse(0)
        rd_disable = (word0 >> 19) & 0x1

        if rd_disable == 0:
            """ we can read the flash_crypt_config efuse value
            so go & read it (EFUSE_BLK0_RDATA5_REG[31:28]) """
            word5 = self.read_efuse(5)
            word5 = (word5 >> 28) & 0xF
            return word5
        else:
            # if read of the efuse is disabled we assume it is set correctly
            return 0xF

    def get_encrypted_download_disabled(self):
        if self.read_reg(self.EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT_REG) & self.EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT:
            return True
        else:
            return False

    def get_pkg_version(self):
        word3 = self.read_efuse(3)
        pkg_version = (word3 >> 9) & 0x07
        pkg_version += ((word3 >> 2) & 0x1) << 3
        return pkg_version

    # Returns new version format based on major and minor versions
    def get_chip_full_revision(self):
        return self.get_major_chip_version() * 100 + self.get_minor_chip_version()

    # Returns old version format (ECO number). Use the new format get_chip_full_revision().
    def get_chip_revision(self):
        return self.get_major_chip_version()

    def get_minor_chip_version(self):
        return (self.read_efuse(5) >> 24) & 0x3

    def get_major_chip_version(self):
        rev_bit0 = (self.read_efuse(3) >> 15) & 0x1
        rev_bit1 = (self.read_efuse(5) >> 20) & 0x1
        apb_ctl_date = self.read_reg(self.APB_CTL_DATE_ADDR)
        rev_bit2 = (apb_ctl_date >> self.APB_CTL_DATE_S) & self.APB_CTL_DATE_V
        combine_value = (rev_bit2 << 2) | (rev_bit1 << 1) | rev_bit0

        revision = {
            0: 0,
            1: 1,
            3: 2,
            7: 3,
        }.get(combine_value, 0)
        return revision

    def get_chip_description(self):
        pkg_version = self.get_pkg_version()
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        rev3 = major_rev == 3
        single_core = self.read_efuse(3) & (1 << 0)  # CHIP_VER DIS_APP_CPU

        chip_name = {
            0: "ESP32-S0WDQ6" if single_core else "ESP32-D0WDQ6",
            1: "ESP32-S0WDQ5" if single_core else "ESP32-D0WDQ5",
            2: "ESP32-S2WDQ5" if single_core else "ESP32-D2WDQ5",
            3: "ESP32-S0WD-OEM" if single_core else "ESP32-D0WD-OEM",
            4: "ESP32-U4WDH",
            5: "ESP32-PICO-V3" if rev3 else "ESP32-PICO-D4",
            6: "ESP32-PICO-V3-02",
            7: "ESP32-D0WDR2-V3",
        }.get(pkg_version, "unknown ESP32")

        # ESP32-D0WD-V3, ESP32-D0WDQ6-V3
        if chip_name.startswith("ESP32-D0WD") and rev3:
            chip_name += "-V3"

        return "%s (revision v%d.%d)" % (chip_name, major_rev, minor_rev)

    def get_chip_features(self):
        features = ["WiFi"]
        word3 = self.read_efuse(3)

        # names of variables in this section are lowercase
        #  versions of EFUSE names as documented in TRM and
        # ESP-IDF efuse_reg.h

        chip_ver_dis_bt = word3 & (1 << 1)
        if chip_ver_dis_bt == 0:
            features += ["BT"]

        chip_ver_dis_app_cpu = word3 & (1 << 0)
        if chip_ver_dis_app_cpu:
            features += ["Single Core"]
        else:
            features += ["Dual Core"]

        chip_cpu_freq_rated = word3 & (1 << 13)
        if chip_cpu_freq_rated:
            chip_cpu_freq_low = word3 & (1 << 12)
            if chip_cpu_freq_low:
                features += ["160MHz"]
            else:
                features += ["240MHz"]

        pkg_version = self.get_pkg_version()
        if pkg_version in [2, 4, 5, 6]:
            features += ["Embedded Flash"]

        if pkg_version == 6:
            features += ["Embedded PSRAM"]

        word4 = self.read_efuse(4)
        adc_vref = (word4 >> 8) & 0x1F
        if adc_vref:
            features += ["VRef calibration in efuse"]

        blk3_part_res = word3 >> 14 & 0x1
        if blk3_part_res:
            features += ["BLK3 partially reserved"]

        word6 = self.read_efuse(6)
        coding_scheme = word6 & 0x3
        features += ["Coding Scheme %s" % {
            0: "None",
            1: "3/4",
            2: "Repeat (UNSUPPORTED)",
            3: "Invalid"}[coding_scheme]]

        return features

    def read_efuse(self, n):
        """ Read the nth word of the ESP3x EFUSE region. """
        return self.read_reg(self.EFUSE_RD_REG_BASE + (4 * n))

    def chip_id(self):
        raise NotSupportedError(self, "chip_id")

    def read_mac(self):
        """ Read MAC from EFUSE region """
        words = [self.read_efuse(2), self.read_efuse(1)]
        bitstring = struct.pack(">II", *words)
        bitstring = bitstring[2:8]  # trim the 2 byte CRC
        try:
            return tuple(ord(b) for b in bitstring)
        except TypeError:  # Python 3, bitstring elements are already bytes
            return tuple(bitstring)

    def get_erase_size(self, offset, size):
        return size

    def override_vddsdio(self, new_voltage):
        new_voltage = new_voltage.upper()
        if new_voltage not in self.OVERRIDE_VDDSDIO_CHOICES:
            raise FatalError("The only accepted VDDSDIO overrides are '1.8V', '1.9V' and 'OFF'")
        RTC_CNTL_SDIO_CONF_REG = 0x3ff48074
        RTC_CNTL_XPD_SDIO_REG = (1 << 31)
        RTC_CNTL_DREFH_SDIO_M = (3 << 29)
        RTC_CNTL_DREFM_SDIO_M = (3 << 27)
        RTC_CNTL_DREFL_SDIO_M = (3 << 25)
        # RTC_CNTL_SDIO_TIEH = (1 << 23)  # not used here, setting TIEH=1 would set 3.3V output, not safe for esptool.py to do
        RTC_CNTL_SDIO_FORCE = (1 << 22)
        RTC_CNTL_SDIO_PD_EN = (1 << 21)

        reg_val = RTC_CNTL_SDIO_FORCE  # override efuse setting
        reg_val |= RTC_CNTL_SDIO_PD_EN
        if new_voltage != "OFF":
            reg_val |= RTC_CNTL_XPD_SDIO_REG  # enable internal LDO
        if new_voltage == "1.9V":
            reg_val |= (RTC_CNTL_DREFH_SDIO_M | RTC_CNTL_DREFM_SDIO_M | RTC_CNTL_DREFL_SDIO_M)  # boost voltage
        self.write_reg(RTC_CNTL_SDIO_CONF_REG, reg_val)
        print("VDDSDIO regulator set to %s" % new_voltage)

    def read_flash_slow(self, offset, length, progress_fn):
        BLOCK_LEN = 64  # ROM read limit per command (this limit is why it's so slow)

        data = b''
        while len(data) < length:
            block_len = min(BLOCK_LEN, length - len(data))
            r = self.check_command("read flash block", self.ESP_READ_FLASH_SLOW,
                                   struct.pack('<II', offset + len(data), block_len))
            if len(r) < block_len:
                raise FatalError("Expected %d byte block, got %d bytes. Serial errors?" % (block_len, len(r)))
            data += r[:block_len]  # command always returns 64 byte buffer, regardless of how many bytes were actually read from flash
            if progress_fn and (len(data) % 1024 == 0 or len(data) == length):
                progress_fn(len(data), length)
        return data


class ESP32S2ROM(ESP32ROM):
    CHIP_NAME = "ESP32-S2"
    IMAGE_CHIP_ID = 2

    IROM_MAP_START = 0x40080000
    IROM_MAP_END = 0x40B80000
    DROM_MAP_START = 0x3F000000
    DROM_MAP_END = 0x3F3F0000

    CHIP_DETECT_MAGIC_VALUE = [0x000007C6]

    SPI_REG_BASE = 0x3F402000
    SPI_USR_OFFS = 0x18
    SPI_USR1_OFFS = 0x1C
    SPI_USR2_OFFS = 0x20
    SPI_MOSI_DLEN_OFFS = 0x24
    SPI_MISO_DLEN_OFFS = 0x28
    SPI_W0_OFFS = 0x58

    MAC_EFUSE_REG = 0x3F41A044  # ESP32-S2 has special block for MAC efuses

    UART_CLKDIV_REG = 0x3F400014

    SUPPORTS_ENCRYPTED_FLASH = True

    FLASH_ENCRYPTED_WRITE_ALIGN = 16

    # todo: use espefuse APIs to get this info
    EFUSE_BASE = 0x3F41A000
    EFUSE_RD_REG_BASE = EFUSE_BASE + 0x030  # BLOCK0 read base address
    EFUSE_BLOCK1_ADDR = EFUSE_BASE + 0x044
    EFUSE_BLOCK2_ADDR = EFUSE_BASE + 0x05C

    EFUSE_PURPOSE_KEY0_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY0_SHIFT = 24
    EFUSE_PURPOSE_KEY1_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY1_SHIFT = 28
    EFUSE_PURPOSE_KEY2_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY2_SHIFT = 0
    EFUSE_PURPOSE_KEY3_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY3_SHIFT = 4
    EFUSE_PURPOSE_KEY4_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY4_SHIFT = 8
    EFUSE_PURPOSE_KEY5_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY5_SHIFT = 12

    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT_REG = EFUSE_RD_REG_BASE
    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT = 1 << 19

    EFUSE_SPI_BOOT_CRYPT_CNT_REG = EFUSE_BASE + 0x034
    EFUSE_SPI_BOOT_CRYPT_CNT_MASK = 0x7 << 18

    EFUSE_SECURE_BOOT_EN_REG = EFUSE_BASE + 0x038
    EFUSE_SECURE_BOOT_EN_MASK = 1 << 20

    EFUSE_RD_REPEAT_DATA3_REG = EFUSE_BASE + 0x3C
    EFUSE_RD_REPEAT_DATA3_REG_FLASH_TYPE_MASK = 1 << 9

    PURPOSE_VAL_XTS_AES256_KEY_1 = 2
    PURPOSE_VAL_XTS_AES256_KEY_2 = 3
    PURPOSE_VAL_XTS_AES128_KEY = 4

    UARTDEV_BUF_NO = 0x3FFFFD14  # Variable in ROM .bss which indicates the port in use
    UARTDEV_BUF_NO_USB = 2  # Value of the above indicating that USB-OTG is in use

    USB_RAM_BLOCK = 0x800  # Max block size USB-OTG is used

    GPIO_STRAP_REG = 0x3F404038
    GPIO_STRAP_SPI_BOOT_MASK = 1 << 3  # Not download mode
    RTC_CNTL_OPTION1_REG = 0x3F408128
    RTC_CNTL_FORCE_DOWNLOAD_BOOT_MASK = 0x1  # Is download mode forced over USB?

    RTCCNTL_BASE_REG = 0x3F408000
    RTC_CNTL_WDTCONFIG0_REG = RTCCNTL_BASE_REG + 0x0094
    RTC_CNTL_WDTCONFIG1_REG = RTCCNTL_BASE_REG + 0x0098
    RTC_CNTL_WDTWPROTECT_REG = RTCCNTL_BASE_REG + 0x00AC
    RTC_CNTL_WDT_WKEY = 0x50D83AA1

    MEMORY_MAP = [
        [0x00000000, 0x00010000, "PADDING"],
        [0x3F000000, 0x3FF80000, "DROM"],
        [0x3F500000, 0x3FF80000, "EXTRAM_DATA"],
        [0x3FF9E000, 0x3FFA0000, "RTC_DRAM"],
        [0x3FF9E000, 0x40000000, "BYTE_ACCESSIBLE"],
        [0x3FF9E000, 0x40072000, "MEM_INTERNAL"],
        [0x3FFB0000, 0x40000000, "DRAM"],
        [0x40000000, 0x4001A100, "IROM_MASK"],
        [0x40020000, 0x40070000, "IRAM"],
        [0x40070000, 0x40072000, "RTC_IRAM"],
        [0x40080000, 0x40800000, "IROM"],
        [0x50000000, 0x50002000, "RTC_DATA"],
    ]

    UF2_FAMILY_ID = 0xBFDD4EEE

    # Returns old version format (ECO number). Use the new format get_chip_full_revision().
    def get_chip_revision(self):
        return self.get_major_chip_version()

    def get_pkg_version(self):
        num_word = 4
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 0) & 0x0F

    def get_minor_chip_version(self):
        hi_num_word = 3
        hi = (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * hi_num_word)) >> 20) & 0x01
        low_num_word = 4
        low = (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * low_num_word)) >> 4) & 0x07
        return (hi << 3) + low

    def get_major_chip_version(self):
        num_word = 3
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 18) & 0x03

    def get_flash_version(self):
        num_word = 3
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 21) & 0x0F

    def get_flash_cap(self):
        return self.get_flash_version()

    def get_psram_version(self):
        num_word = 3
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 28) & 0x0F

    def get_psram_cap(self):
        return self.get_psram_version()

    def get_block2_version(self):
        # BLK_VERSION_MINOR
        num_word = 4
        return (self.read_reg(self.EFUSE_BLOCK2_ADDR + (4 * num_word)) >> 4) & 0x07

    def get_chip_description(self):
        chip_name = {
            0: "ESP32-S2",
            1: "ESP32-S2FH2",
            2: "ESP32-S2FH4",
            102: "ESP32-S2FNR2",
            100: "ESP32-S2R2",
        }.get(
            self.get_flash_cap() + self.get_psram_cap() * 100,
            "unknown ESP32-S2",
        )
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        return f"{chip_name} (revision v{major_rev}.{minor_rev})"

    def get_chip_features(self):
        features = ["WiFi"]

        if self.secure_download_mode:
            features += ["Secure Download Mode Enabled"]

        flash_version = {
            0: "No Embedded Flash",
            1: "Embedded Flash 2MB",
            2: "Embedded Flash 4MB",
        }.get(self.get_flash_cap(), "Unknown Embedded Flash")
        features += [flash_version]

        psram_version = {
            0: "No Embedded PSRAM",
            1: "Embedded PSRAM 2MB",
            2: "Embedded PSRAM 4MB",
        }.get(self.get_psram_cap(), "Unknown Embedded PSRAM")
        features += [psram_version]

        block2_version = {
            0: "No calibration in BLK2 of efuse",
            1: "ADC and temperature sensor calibration in BLK2 of efuse V1",
            2: "ADC and temperature sensor calibration in BLK2 of efuse V2",
        }.get(self.get_block2_version(), "Unknown Calibration in BLK2")
        features += [block2_version]

        return features

    def get_crystal_freq(self):
        # ESP32-S2 XTAL is fixed to 40MHz
        return 40

    def override_vddsdio(self, new_voltage):
        raise NotImplementedInROMError(
            "VDD_SDIO overrides are not supported for ESP32-S2"
        )

    def read_mac(self, mac_type="BASE_MAC"):
        """Read MAC from EFUSE region"""
        if mac_type != "BASE_MAC":
            return None
        mac0 = self.read_reg(self.MAC_EFUSE_REG)
        mac1 = self.read_reg(self.MAC_EFUSE_REG + 4)  # only bottom 16 bits are MAC
        bitstring = struct.pack(">II", mac1, mac0)[2:]
        return tuple(bitstring)

    def flash_type(self):
        return (
            1
            if self.read_reg(self.EFUSE_RD_REPEAT_DATA3_REG)
            & self.EFUSE_RD_REPEAT_DATA3_REG_FLASH_TYPE_MASK
            else 0
        )

    def get_flash_crypt_config(self):
        return None  # doesn't exist on ESP32-S2

    def get_secure_boot_enabled(self):
        return (
            self.read_reg(self.EFUSE_SECURE_BOOT_EN_REG)
            & self.EFUSE_SECURE_BOOT_EN_MASK
        )

    def get_key_block_purpose(self, key_block):
        if key_block < 0 or key_block > 5:
            raise FatalError("Valid key block numbers must be in range 0-5")

        reg, shift = [
            (self.EFUSE_PURPOSE_KEY0_REG, self.EFUSE_PURPOSE_KEY0_SHIFT),
            (self.EFUSE_PURPOSE_KEY1_REG, self.EFUSE_PURPOSE_KEY1_SHIFT),
            (self.EFUSE_PURPOSE_KEY2_REG, self.EFUSE_PURPOSE_KEY2_SHIFT),
            (self.EFUSE_PURPOSE_KEY3_REG, self.EFUSE_PURPOSE_KEY3_SHIFT),
            (self.EFUSE_PURPOSE_KEY4_REG, self.EFUSE_PURPOSE_KEY4_SHIFT),
            (self.EFUSE_PURPOSE_KEY5_REG, self.EFUSE_PURPOSE_KEY5_SHIFT),
        ][key_block]
        return (self.read_reg(reg) >> shift) & 0xF

    def is_flash_encryption_key_valid(self):
        # Need to see either an AES-128 key or two AES-256 keys
        purposes = [self.get_key_block_purpose(b) for b in range(6)]

        if any(p == self.PURPOSE_VAL_XTS_AES128_KEY for p in purposes):
            return True

        return any(p == self.PURPOSE_VAL_XTS_AES256_KEY_1 for p in purposes) and any(
            p == self.PURPOSE_VAL_XTS_AES256_KEY_2 for p in purposes
        )

    def uses_usb(self, _cache=[]):
        if self.secure_download_mode:
            return False  # can't detect native USB in secure download mode
        if not _cache:
            buf_no = self.read_reg(self.UARTDEV_BUF_NO) & 0xff
            _cache.append(buf_no == self.UARTDEV_BUF_NO_USB)
        return _cache[0]

    def _post_connect(self):
        if self.uses_usb():
            self.ESP_RAM_BLOCK = self.USB_RAM_BLOCK

    def rtc_wdt_reset(self):
        print("Hard resetting with RTC WDT...")
        self.write_reg(self.RTC_CNTL_WDTWPROTECT_REG, self.RTC_CNTL_WDT_WKEY)  # unlock
        self.write_reg(self.RTC_CNTL_WDTCONFIG1_REG, 5000)  # set WDT timeout
        self.write_reg(
            self.RTC_CNTL_WDTCONFIG0_REG, (1 << 31) | (5 << 28) | (1 << 8) | 2
        )  # enable WDT
        self.write_reg(self.RTC_CNTL_WDTWPROTECT_REG, 0)  # lock

    def hard_reset(self):
        if self.uses_usb():
            # Check the strapping register to see if we can perform RTC WDT reset
            strap_reg = self.read_reg(self.GPIO_STRAP_REG)
            force_dl_reg = self.read_reg(self.RTC_CNTL_OPTION1_REG)
            if (
                strap_reg & self.GPIO_STRAP_SPI_BOOT_MASK == 0  # GPIO0 low
                and force_dl_reg & self.RTC_CNTL_FORCE_DOWNLOAD_BOOT_MASK == 0
            ):
                self.rtc_wdt_reset()
                return

        print('Hard resetting via RTS pin...')
        self._setRTS(True)  # EN->LOW
        if self.uses_usb():
            # Give the chip some time to come out of reset, to be able to handle further DTR/RTS transitions
            time.sleep(0.2)
            self._setRTS(False)
            time.sleep(0.2)
        else:
            time.sleep(0.1)
            self._setRTS(False)


class ESP32S3ROM(ESP32ROM):
    CHIP_NAME = "ESP32-S3"

    IMAGE_CHIP_ID = 9

    CHIP_DETECT_MAGIC_VALUE = [0x9]

    FPGA_SLOW_BOOT = False

    IROM_MAP_START = 0x42000000
    IROM_MAP_END = 0x44000000
    DROM_MAP_START = 0x3C000000
    DROM_MAP_END = 0x3E000000

    UART_DATE_REG_ADDR = 0x60000080

    SPI_REG_BASE = 0x60002000
    SPI_USR_OFFS = 0x18
    SPI_USR1_OFFS = 0x1C
    SPI_USR2_OFFS = 0x20
    SPI_MOSI_DLEN_OFFS = 0x24
    SPI_MISO_DLEN_OFFS = 0x28
    SPI_W0_OFFS = 0x58

    SPI_ADDR_REG_MSB = False

    BOOTLOADER_FLASH_OFFSET = 0x0

    SUPPORTS_ENCRYPTED_FLASH = True

    FLASH_ENCRYPTED_WRITE_ALIGN = 16

    # todo: use espefuse APIs to get this info
    EFUSE_BASE = 0x60007000  # BLOCK0 read base address
    EFUSE_BLOCK1_ADDR = EFUSE_BASE + 0x44
    EFUSE_BLOCK2_ADDR = EFUSE_BASE + 0x5C
    MAC_EFUSE_REG = EFUSE_BASE + 0x044

    EFUSE_RD_REG_BASE = EFUSE_BASE + 0x030  # BLOCK0 read base address

    EFUSE_PURPOSE_KEY0_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY0_SHIFT = 24
    EFUSE_PURPOSE_KEY1_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY1_SHIFT = 28
    EFUSE_PURPOSE_KEY2_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY2_SHIFT = 0
    EFUSE_PURPOSE_KEY3_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY3_SHIFT = 4
    EFUSE_PURPOSE_KEY4_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY4_SHIFT = 8
    EFUSE_PURPOSE_KEY5_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY5_SHIFT = 12

    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT_REG = EFUSE_RD_REG_BASE
    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT = 1 << 20

    EFUSE_SPI_BOOT_CRYPT_CNT_REG = EFUSE_BASE + 0x034
    EFUSE_SPI_BOOT_CRYPT_CNT_MASK = 0x7 << 18

    EFUSE_SECURE_BOOT_EN_REG = EFUSE_BASE + 0x038
    EFUSE_SECURE_BOOT_EN_MASK = 1 << 20

    EFUSE_RD_REPEAT_DATA3_REG = EFUSE_BASE + 0x3C
    EFUSE_RD_REPEAT_DATA3_REG_FLASH_TYPE_MASK = 1 << 9

    PURPOSE_VAL_XTS_AES256_KEY_1 = 2
    PURPOSE_VAL_XTS_AES256_KEY_2 = 3
    PURPOSE_VAL_XTS_AES128_KEY = 4

    UARTDEV_BUF_NO = 0x3FCEF14C  # Variable in ROM .bss which indicates the port in use
    UARTDEV_BUF_NO_USB = 3  # The above var when USB-OTG is used
    UARTDEV_BUF_NO_USB_JTAG_SERIAL = 4  # The above var when USB-JTAG/Serial is used

    RTCCNTL_BASE_REG = 0x60008000
    RTC_CNTL_SWD_CONF_REG = RTCCNTL_BASE_REG + 0x00B4
    RTC_CNTL_SWD_AUTO_FEED_EN = 1 << 31
    RTC_CNTL_SWD_WPROTECT_REG = RTCCNTL_BASE_REG + 0x00B8
    RTC_CNTL_SWD_WKEY = 0x8F1D312A

    RTC_CNTL_WDTCONFIG0_REG = RTCCNTL_BASE_REG + 0x0098
    RTC_CNTL_WDTCONFIG1_REG = RTCCNTL_BASE_REG + 0x009C
    RTC_CNTL_WDTWPROTECT_REG = RTCCNTL_BASE_REG + 0x00B0
    RTC_CNTL_WDT_WKEY = 0x50D83AA1

    USB_RAM_BLOCK = 0x800  # Max block size USB-OTG is used

    GPIO_STRAP_REG = 0x60004038
    GPIO_STRAP_SPI_BOOT_MASK = 1 << 3  # Not download mode
    RTC_CNTL_OPTION1_REG = 0x6000812C
    RTC_CNTL_FORCE_DOWNLOAD_BOOT_MASK = 0x1  # Is download mode forced over USB?

    UART_CLKDIV_REG = 0x60000014

    MEMORY_MAP = [[0x00000000, 0x00010000, "PADDING"],
                  [0x3C000000, 0x3D000000, "DROM"],
                  [0x3D000000, 0x3E000000, "EXTRAM_DATA"],
                  [0x600FE000, 0x60100000, "RTC_DRAM"],
                  [0x3FC88000, 0x3FD00000, "BYTE_ACCESSIBLE"],
                  [0x3FC88000, 0x403E2000, "MEM_INTERNAL"],
                  [0x3FC88000, 0x3FD00000, "DRAM"],
                  [0x40000000, 0x4001A100, "IROM_MASK"],
                  [0x40370000, 0x403E0000, "IRAM"],
                  [0x600FE000, 0x60100000, "RTC_IRAM"],
                  [0x42000000, 0x42800000, "IROM"],
                  [0x50000000, 0x50002000, "RTC_DATA"]]

    # Returns old version format (ECO number). Use the new format get_chip_full_revision().
    def get_chip_revision(self):
        return self.get_minor_chip_version()

    def get_pkg_version(self):
        num_word = 3
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 21) & 0x07

    def is_eco0(self, minor_raw):
        # Workaround: The major version field was allocated to other purposes
        # when block version is v1.1.
        # Luckily only chip v0.0 have this kind of block version and efuse usage.
        return (
            (minor_raw & 0x7) == 0 and self.get_blk_version_major() == 1 and self.get_blk_version_minor() == 1
        )

    def get_minor_chip_version(self):
        minor_raw = self.get_raw_minor_chip_version()
        if self.is_eco0(minor_raw):
            return 0
        return minor_raw

    def get_raw_minor_chip_version(self):
        hi_num_word = 5
        hi = (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * hi_num_word)) >> 23) & 0x01
        low_num_word = 3
        low = (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * low_num_word)) >> 18) & 0x07
        return (hi << 3) + low

    def get_blk_version_major(self):
        num_word = 4
        return (self.read_reg(self.EFUSE_BLOCK2_ADDR + (4 * num_word)) >> 0) & 0x03

    def get_blk_version_minor(self):
        num_word = 3
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 24) & 0x07

    def get_major_chip_version(self):
        minor_raw = self.get_raw_minor_chip_version()
        if self.is_eco0(minor_raw):
            return 0
        return self.get_raw_major_chip_version()

    def get_raw_major_chip_version(self):
        num_word = 5
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 24) & 0x03

    def get_chip_description(self):
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        pkg_version = self.get_pkg_version()

        chip_name = {
            0: "ESP32-S3 (QFN56)",
            1: "ESP32-S3-PICO-1 (LGA56)",
        }.get(pkg_version, "Unknown ESP32-S3")

        return f"{chip_name} (revision v{major_rev}.{minor_rev})"

    def get_flash_cap(self):
        num_word = 3
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 27) & 0x07

    def get_flash_vendor(self):
        num_word = 4
        vendor_id = (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 0) & 0x07
        return {1: "XMC", 2: "GD", 3: "FM", 4: "TT", 5: "BY"}.get(vendor_id, "")

    def get_psram_cap(self):
        num_word = 4
        psram_cap = (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 3) & 0x03
        num_word = 5
        psram_cap_hi_bit = (
            self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 19
        ) & 0x01
        return (psram_cap_hi_bit << 2) | psram_cap

    def get_psram_vendor(self):
        num_word = 4
        vendor_id = (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 7) & 0x03
        return {1: "AP_3v3", 2: "AP_1v8"}.get(vendor_id, "")

    def get_chip_features(self):
        features = ["Wi-Fi", "BT 5 (LE)", "Dual Core + LP Core", "240MHz"]

        flash = {
            0: None,
            1: "Embedded Flash 8MB",
            2: "Embedded Flash 4MB",
        }.get(self.get_flash_cap(), "Unknown Embedded Flash")
        if flash is not None:
            features += [flash + f" ({self.get_flash_vendor()})"]

        psram = {
            0: None,
            1: "Embedded PSRAM 8MB",
            2: "Embedded PSRAM 2MB",
            3: "Embedded PSRAM 16MB",
            4: "Embedded PSRAM 4MB",
        }.get(self.get_psram_cap(), "Unknown Embedded PSRAM")
        if psram is not None:
            features += [psram + f" ({self.get_psram_vendor()})"]

        return features

    def get_crystal_freq(self):
        # ESP32S3 XTAL is fixed to 40MHz
        return 40

    def get_flash_crypt_config(self):
        return None  # doesn't exist on ESP32-S3

    def get_key_block_purpose(self, key_block):
        if key_block < 0 or key_block > 5:
            raise FatalError("Valid key block numbers must be in range 0-5")

        reg, shift = [(self.EFUSE_PURPOSE_KEY0_REG, self.EFUSE_PURPOSE_KEY0_SHIFT),
                      (self.EFUSE_PURPOSE_KEY1_REG, self.EFUSE_PURPOSE_KEY1_SHIFT),
                      (self.EFUSE_PURPOSE_KEY2_REG, self.EFUSE_PURPOSE_KEY2_SHIFT),
                      (self.EFUSE_PURPOSE_KEY3_REG, self.EFUSE_PURPOSE_KEY3_SHIFT),
                      (self.EFUSE_PURPOSE_KEY4_REG, self.EFUSE_PURPOSE_KEY4_SHIFT),
                      (self.EFUSE_PURPOSE_KEY5_REG, self.EFUSE_PURPOSE_KEY5_SHIFT)][key_block]
        return (self.read_reg(reg) >> shift) & 0xF

    def is_flash_encryption_key_valid(self):
        # Need to see either an AES-128 key or two AES-256 keys
        purposes = [self.get_key_block_purpose(b) for b in range(6)]

        if any(p == self.PURPOSE_VAL_XTS_AES128_KEY for p in purposes):
            return True

        return any(p == self.PURPOSE_VAL_XTS_AES256_KEY_1 for p in purposes) \
            and any(p == self.PURPOSE_VAL_XTS_AES256_KEY_2 for p in purposes)

    def override_vddsdio(self, new_voltage):
        raise NotImplementedInROMError("VDD_SDIO overrides are not supported for ESP32-S3")

    def read_mac(self):
        mac0 = self.read_reg(self.MAC_EFUSE_REG)
        mac1 = self.read_reg(self.MAC_EFUSE_REG + 4)  # only bottom 16 bits are MAC
        bitstring = struct.pack(">II", mac1, mac0)[2:]
        try:
            return tuple(ord(b) for b in bitstring)
        except TypeError:  # Python 3, bitstring elements are already bytes
            return tuple(bitstring)

    def uses_usb(self, _cache=[]):
        if self.secure_download_mode:
            return False  # can't detect native USB in secure download mode
        if not _cache:
            buf_no = self.read_reg(self.UARTDEV_BUF_NO) & 0xff
            _cache.append(buf_no == self.UARTDEV_BUF_NO_USB)
        return _cache[0]

    def uses_usb_jtag_serial(self, _cache=[]):
        """
        Check the UARTDEV_BUF_NO register to see if USB-JTAG/Serial is being used
        """
        if self.secure_download_mode:
            return False  # can't detect USB-JTAG/Serial in secure download mode
        if not _cache:
            buf_no = self.read_reg(self.UARTDEV_BUF_NO) & 0xff
            _cache.append(buf_no == self.UARTDEV_BUF_NO_USB_JTAG_SERIAL)
        return _cache[0]

    def _post_connect(self):
        if self.uses_usb():
            self.ESP_RAM_BLOCK = self.USB_RAM_BLOCK

    def rtc_wdt_reset(self):
        print("Hard resetting with RTC WDT...")
        self.write_reg(self.RTC_CNTL_WDTWPROTECT_REG, self.RTC_CNTL_WDT_WKEY)  # unlock
        self.write_reg(self.RTC_CNTL_WDTCONFIG1_REG, 5000)  # set WDT timeout
        self.write_reg(
            self.RTC_CNTL_WDTCONFIG0_REG, (1 << 31) | (5 << 28) | (1 << 8) | 2
        )  # enable WDT
        self.write_reg(self.RTC_CNTL_WDTWPROTECT_REG, 0)  # lock

    def hard_reset(self):
        try:
            # Clear force download boot mode to avoid the chip being stuck in download mode after reset
            # workaround for issue: https://github.com/espressif/arduino-esp32/issues/6762
            self.write_reg(
                self.RTC_CNTL_OPTION1_REG, 0, self.RTC_CNTL_FORCE_DOWNLOAD_BOOT_MASK
            )
        except Exception:
            # Skip if response was not valid and proceed to reset; e.g. when monitoring while resetting
            pass
        uses_usb_otg = self.uses_usb()
        if uses_usb_otg or self.uses_usb_jtag_serial():
            # Check the strapping register to see if we can perform RTC WDT reset
            strap_reg = self.read_reg(self.GPIO_STRAP_REG)
            force_dl_reg = self.read_reg(self.RTC_CNTL_OPTION1_REG)
            if (
                strap_reg & self.GPIO_STRAP_SPI_BOOT_MASK == 0  # GPIO0 low
                and force_dl_reg & self.RTC_CNTL_FORCE_DOWNLOAD_BOOT_MASK == 0
            ):
                self.rtc_wdt_reset()
                return

        print('Hard resetting via RTS pin...')
        self._setRTS(True)  # EN->LOW
        if self.uses_usb():
            # Give the chip some time to come out of reset, to be able to handle further DTR/RTS transitions
            time.sleep(0.2)
            self._setRTS(False)
            time.sleep(0.2)
        else:
            time.sleep(0.1)
            self._setRTS(False)


class ESP32C3ROM(ESP32ROM):
    CHIP_NAME = "ESP32-C3"
    IMAGE_CHIP_ID = 5

    FPGA_SLOW_BOOT = False

    IROM_MAP_START = 0x42000000
    IROM_MAP_END = 0x42800000
    DROM_MAP_START = 0x3C000000
    DROM_MAP_END = 0x3C800000

    SPI_REG_BASE = 0x60002000
    SPI_USR_OFFS = 0x18
    SPI_USR1_OFFS = 0x1C
    SPI_USR2_OFFS = 0x20
    SPI_MOSI_DLEN_OFFS = 0x24
    SPI_MISO_DLEN_OFFS = 0x28
    SPI_W0_OFFS = 0x58

    SPI_ADDR_REG_MSB = False

    BOOTLOADER_FLASH_OFFSET = 0x0

    # Magic values for ESP32-C3 eco 1+2, eco 3, eco 6, and eco 7 respectively
    CHIP_DETECT_MAGIC_VALUE = [0x6921506F, 0x1B31506F, 0x4881606F, 0x4361606F]

    UART_DATE_REG_ADDR = 0x60000000 + 0x7C

    UART_CLKDIV_REG = 0x60000014

    EFUSE_BASE = 0x60008800
    EFUSE_BLOCK1_ADDR = EFUSE_BASE + 0x044
    MAC_EFUSE_REG = EFUSE_BASE + 0x044

    EFUSE_RD_REG_BASE = EFUSE_BASE + 0x030  # BLOCK0 read base address

    EFUSE_PURPOSE_KEY0_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY0_SHIFT = 24
    EFUSE_PURPOSE_KEY1_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY1_SHIFT = 28
    EFUSE_PURPOSE_KEY2_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY2_SHIFT = 0
    EFUSE_PURPOSE_KEY3_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY3_SHIFT = 4
    EFUSE_PURPOSE_KEY4_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY4_SHIFT = 8
    EFUSE_PURPOSE_KEY5_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY5_SHIFT = 12

    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT_REG = EFUSE_RD_REG_BASE
    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT = 1 << 20

    EFUSE_SPI_BOOT_CRYPT_CNT_REG = EFUSE_BASE + 0x034
    EFUSE_SPI_BOOT_CRYPT_CNT_MASK = 0x7 << 18

    EFUSE_SECURE_BOOT_EN_REG = EFUSE_BASE + 0x038
    EFUSE_SECURE_BOOT_EN_MASK = 1 << 20

    PURPOSE_VAL_XTS_AES128_KEY = 4

    GPIO_STRAP_REG = 0x3f404038

    SUPPORTS_ENCRYPTED_FLASH = True

    FLASH_ENCRYPTED_WRITE_ALIGN = 16

    UARTDEV_BUF_NO = 0x3FCDF07C  # Variable in ROM .bss which indicates the port in use
    UARTDEV_BUF_NO_USB_JTAG_SERIAL = 3  # The above var when USB-JTAG/Serial is used

    RTCCNTL_BASE_REG = 0x60008000
    RTC_CNTL_SWD_CONF_REG = RTCCNTL_BASE_REG + 0x00AC
    RTC_CNTL_SWD_AUTO_FEED_EN = 1 << 31
    RTC_CNTL_SWD_WPROTECT_REG = RTCCNTL_BASE_REG + 0x00B0
    RTC_CNTL_SWD_WKEY = 0x8F1D312A

    RTC_CNTL_WDTCONFIG0_REG = RTCCNTL_BASE_REG + 0x0090
    RTC_CNTL_WDTCONFIG1_REG = RTCCNTL_BASE_REG + 0x0094
    RTC_CNTL_WDTWPROTECT_REG = RTCCNTL_BASE_REG + 0x00A8
    RTC_CNTL_WDT_WKEY = 0x50D83AA1

    MEMORY_MAP = [
        [0x00000000, 0x00010000, "PADDING"],
        [0x3C000000, 0x3C800000, "DROM"],
        [0x3FC80000, 0x3FCE0000, "DRAM"],
        [0x3FC88000, 0x3FD00000, "BYTE_ACCESSIBLE"],
        [0x3FF00000, 0x3FF20000, "DROM_MASK"],
        [0x40000000, 0x40060000, "IROM_MASK"],
        [0x42000000, 0x42800000, "IROM"],
        [0x4037C000, 0x403E0000, "IRAM"],
        [0x50000000, 0x50002000, "RTC_IRAM"],
        [0x50000000, 0x50002000, "RTC_DRAM"],
        [0x600FE000, 0x60100000, "MEM_INTERNAL2"],
    ]

    UF2_FAMILY_ID = 0xD42BA06C

    EFUSE_MAX_KEY = 5
    KEY_PURPOSES: Dict[int, str] = {
        0: "USER/EMPTY",
        1: "RESERVED",
        4: "XTS_AES_128_KEY",
        5: "HMAC_DOWN_ALL",
        6: "HMAC_DOWN_JTAG",
        7: "HMAC_DOWN_DIGITAL_SIGNATURE",
        8: "HMAC_UP",
        9: "SECURE_BOOT_DIGEST0",
        10: "SECURE_BOOT_DIGEST1",
        11: "SECURE_BOOT_DIGEST2",
    }

    # Returns old version format (ECO number). Use the new format get_chip_full_revision().
    def get_chip_revision(self):
        return self.get_minor_chip_version()

    def get_pkg_version(self):
        num_word = 3
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 21) & 0x07

    def get_minor_chip_version(self):
        hi_num_word = 5
        hi = (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * hi_num_word)) >> 23) & 0x01
        low_num_word = 3
        low = (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * low_num_word)) >> 18) & 0x07
        return (hi << 3) + low

    def get_major_chip_version(self):
        num_word = 5
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 24) & 0x03

    def get_flash_cap(self):
        num_word = 3
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 27) & 0x07

    def get_flash_vendor(self):
        num_word = 4
        vendor_id = (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 0) & 0x07
        return {1: "XMC", 2: "GD", 3: "FM", 4: "TT", 5: "ZBIT"}.get(vendor_id, "")

    def get_chip_description(self):
        chip_name = {
            0: "ESP32-C3 (QFN32)",
            1: "ESP8685 (QFN28)",
            2: "ESP32-C3 AZ (QFN32)",
            3: "ESP8686 (QFN24)",
        }.get(self.get_pkg_version(), "unknown ESP32-C3")
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        return f"{chip_name} (revision v{major_rev}.{minor_rev})"

    def get_chip_features(self):
        features = ["Wi-Fi", "BT 5 (LE)", "Single Core", "160MHz"]

        flash = {
            0: None,
            1: "Embedded Flash 4MB",
            2: "Embedded Flash 2MB",
            3: "Embedded Flash 1MB",
            4: "Embedded Flash 8MB",
        }.get(self.get_flash_cap(), "Unknown Embedded Flash")
        if flash is not None:
            features += [flash + f" ({self.get_flash_vendor()})"]
        return features

    def get_crystal_freq(self):
        # ESP32C3 XTAL is fixed to 40MHz
        return 40

    def get_flash_voltage(self):
        pass  # not supported on ESP32-C3

    def override_vddsdio(self, new_voltage):
        raise NotImplementedInROMError(
            "VDD_SDIO overrides are not supported for ESP32-C3"
        )

    def read_mac(self, mac_type="BASE_MAC"):
        """Read MAC from EFUSE region"""
        if mac_type != "BASE_MAC":
            return None
        mac0 = self.read_reg(self.MAC_EFUSE_REG)
        mac1 = self.read_reg(self.MAC_EFUSE_REG + 4)  # only bottom 16 bits are MAC
        bitstring = struct.pack(">II", mac1, mac0)[2:]
        return tuple(bitstring)

    def get_flash_crypt_config(self):
        return None  # doesn't exist on ESP32-C3

    def get_secure_boot_enabled(self):
        return (
            self.read_reg(self.EFUSE_SECURE_BOOT_EN_REG)
            & self.EFUSE_SECURE_BOOT_EN_MASK
        )

    def get_key_block_purpose(self, key_block):
        if key_block < 0 or key_block > self.EFUSE_MAX_KEY:
            raise FatalError(
                f"Valid key block numbers must be in range 0-{self.EFUSE_MAX_KEY}"
            )

        reg, shift = [
            (self.EFUSE_PURPOSE_KEY0_REG, self.EFUSE_PURPOSE_KEY0_SHIFT),
            (self.EFUSE_PURPOSE_KEY1_REG, self.EFUSE_PURPOSE_KEY1_SHIFT),
            (self.EFUSE_PURPOSE_KEY2_REG, self.EFUSE_PURPOSE_KEY2_SHIFT),
            (self.EFUSE_PURPOSE_KEY3_REG, self.EFUSE_PURPOSE_KEY3_SHIFT),
            (self.EFUSE_PURPOSE_KEY4_REG, self.EFUSE_PURPOSE_KEY4_SHIFT),
            (self.EFUSE_PURPOSE_KEY5_REG, self.EFUSE_PURPOSE_KEY5_SHIFT),
        ][key_block]
        return (self.read_reg(reg) >> shift) & 0xF

    def is_flash_encryption_key_valid(self):
        # Need to see an AES-128 key
        purposes = [
            self.get_key_block_purpose(b) for b in range(self.EFUSE_MAX_KEY + 1)
        ]

        return any(p == self.PURPOSE_VAL_XTS_AES128_KEY for p in purposes)

    def uses_usb_jtag_serial(self, _cache=[]):
        """
        Check the UARTDEV_BUF_NO register to see if USB-JTAG/Serial is being used
        """
        if self.secure_download_mode:
            return False  # can't detect USB-JTAG/Serial in secure download mode
        if not _cache:
            buf_no = self.read_reg(self.UARTDEV_BUF_NO) & 0xff
            _cache.append(buf_no == self.UARTDEV_BUF_NO_USB_JTAG_SERIAL)
        return _cache[0]

    def disable_watchdogs(self):
        # When USB-JTAG/Serial is used, the RTC WDT and SWD watchdog are not reset
        # and can then reset the board during flashing. Disable or autofeed them.
        if self.uses_usb_jtag_serial():
            # Disable RTC WDT
            self.write_reg(self.RTC_CNTL_WDTWPROTECT_REG, self.RTC_CNTL_WDT_WKEY)
            self.write_reg(self.RTC_CNTL_WDTCONFIG0_REG, 0)
            self.write_reg(self.RTC_CNTL_WDTWPROTECT_REG, 0)

            # Automatically feed SWD
            self.write_reg(self.RTC_CNTL_SWD_WPROTECT_REG, self.RTC_CNTL_SWD_WKEY)
            self.write_reg(
                self.RTC_CNTL_SWD_CONF_REG,
                self.read_reg(self.RTC_CNTL_SWD_CONF_REG)
                | self.RTC_CNTL_SWD_AUTO_FEED_EN,
            )
            self.write_reg(self.RTC_CNTL_SWD_WPROTECT_REG, 0)

    def _post_connect(self):
        if not self.sync_stub_detected:  # Don't run if stub is reused
            self.disable_watchdogs()

    def hard_reset(self):
        if self.uses_usb_jtag_serial():
            self.rtc_wdt_reset()
        else:
            print('Hard resetting via RTS pin...')
            self._setRTS(True)  # EN->LOW
            time.sleep(0.1)
            self._setRTS(False)

    def rtc_wdt_reset(self):
        print("Hard resetting with RTC WDT...")
        self.write_reg(self.RTC_CNTL_WDTWPROTECT_REG, self.RTC_CNTL_WDT_WKEY)  # unlock
        self.write_reg(self.RTC_CNTL_WDTCONFIG1_REG, 5000)  # set WDT timeout
        self.write_reg(
            self.RTC_CNTL_WDTCONFIG0_REG, (1 << 31) | (5 << 28) | (1 << 8) | 2
        )  # enable WDT
        self.write_reg(self.RTC_CNTL_WDTWPROTECT_REG, 0)  # lock


class ESP32C6ROM(ESP32C3ROM):
    CHIP_NAME = "ESP32-C6"
    IMAGE_CHIP_ID = 13

    FPGA_SLOW_BOOT = False

    IROM_MAP_START = 0x42000000
    IROM_MAP_END = 0x42800000
    DROM_MAP_START = 0x42800000
    DROM_MAP_END = 0x43000000

    BOOTLOADER_FLASH_OFFSET = 0x0

    # Magic value for ESP32C6
    CHIP_DETECT_MAGIC_VALUE = [0x2CE0806F]

    SPI_REG_BASE = 0x60003000
    SPI_USR_OFFS = 0x18
    SPI_USR1_OFFS = 0x1C
    SPI_USR2_OFFS = 0x20
    SPI_MOSI_DLEN_OFFS = 0x24
    SPI_MISO_DLEN_OFFS = 0x28
    SPI_W0_OFFS = 0x58

    UART_DATE_REG_ADDR = 0x60000000 + 0x7C

    EFUSE_BASE = 0x600B0800
    EFUSE_BLOCK1_ADDR = EFUSE_BASE + 0x044
    MAC_EFUSE_REG = EFUSE_BASE + 0x044

    EFUSE_RD_REG_BASE = EFUSE_BASE + 0x030  # BLOCK0 read base address

    EFUSE_PURPOSE_KEY0_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY0_SHIFT = 24
    EFUSE_PURPOSE_KEY1_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY1_SHIFT = 28
    EFUSE_PURPOSE_KEY2_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY2_SHIFT = 0
    EFUSE_PURPOSE_KEY3_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY3_SHIFT = 4
    EFUSE_PURPOSE_KEY4_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY4_SHIFT = 8
    EFUSE_PURPOSE_KEY5_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY5_SHIFT = 12

    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT_REG = EFUSE_RD_REG_BASE
    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT = 1 << 20

    EFUSE_SPI_BOOT_CRYPT_CNT_REG = EFUSE_BASE + 0x034
    EFUSE_SPI_BOOT_CRYPT_CNT_MASK = 0x7 << 18

    EFUSE_SECURE_BOOT_EN_REG = EFUSE_BASE + 0x038
    EFUSE_SECURE_BOOT_EN_MASK = 1 << 20

    PURPOSE_VAL_XTS_AES128_KEY = 4

    SUPPORTS_ENCRYPTED_FLASH = True

    FLASH_ENCRYPTED_WRITE_ALIGN = 16

    UARTDEV_BUF_NO = 0x4087F580  # Variable in ROM .bss which indicates the port in use
    UARTDEV_BUF_NO_USB_JTAG_SERIAL = 3  # The above var when USB-JTAG/Serial is used

    DR_REG_LP_WDT_BASE = 0x600B1C00
    RTC_CNTL_WDTCONFIG0_REG = DR_REG_LP_WDT_BASE + 0x0  # LP_WDT_RWDT_CONFIG0_REG
    RTC_CNTL_WDTCONFIG1_REG = DR_REG_LP_WDT_BASE + 0x0004  # LP_WDT_RWDT_CONFIG1_REG
    RTC_CNTL_WDTWPROTECT_REG = DR_REG_LP_WDT_BASE + 0x0018  # LP_WDT_RWDT_WPROTECT_REG

    RTC_CNTL_SWD_CONF_REG = DR_REG_LP_WDT_BASE + 0x001C  # LP_WDT_SWD_CONFIG_REG
    RTC_CNTL_SWD_AUTO_FEED_EN = 1 << 18
    RTC_CNTL_SWD_WPROTECT_REG = DR_REG_LP_WDT_BASE + 0x0020  # LP_WDT_SWD_WPROTECT_REG
    RTC_CNTL_SWD_WKEY = 0x50D83AA1  # LP_WDT_SWD_WKEY, same as WDT key in this case

    FLASH_FREQUENCY = {
        "80m": 0x0,  # workaround for wrong mspi HS div value in ROM
        "40m": 0x0,
        "20m": 0x2,
    }

    MEMORY_MAP = [
        [0x00000000, 0x00010000, "PADDING"],
        [0x42800000, 0x43000000, "DROM"],
        [0x40800000, 0x40880000, "DRAM"],
        [0x40800000, 0x40880000, "BYTE_ACCESSIBLE"],
        [0x4004AC00, 0x40050000, "DROM_MASK"],
        [0x40000000, 0x4004AC00, "IROM_MASK"],
        [0x42000000, 0x42800000, "IROM"],
        [0x40800000, 0x40880000, "IRAM"],
        [0x50000000, 0x50004000, "RTC_IRAM"],
        [0x50000000, 0x50004000, "RTC_DRAM"],
        [0x600FE000, 0x60100000, "MEM_INTERNAL2"],
    ]

    UF2_FAMILY_ID = 0x540DDF62

    # Returns old version format (ECO number). Use the new format get_chip_full_revision().
    def get_chip_revision(self):
        return self.get_major_chip_version()

    def get_pkg_version(self):
        num_word = 3
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 24) & 0x07

    def get_minor_chip_version(self):
        num_word = 3
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 18) & 0x0F

    def get_major_chip_version(self):
        num_word = 3
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 22) & 0x03

    def get_flash_cap(self):
        num_word = 4
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 0) & 0x07

    def get_chip_description(self):
        pkg_version = self.get_pkg_version()

        chip_name = "Unknown ESP32-C6"
        if pkg_version == 0:
            chip_name = "ESP32-C6 (QFN40)"
        elif pkg_version == 1:
            # Both ESP32-C6FH4 and ESP32-C6FH8 have pkg_version 1
            # so we need to distinguish them by flash_cap
            flash_cap = self.get_flash_cap()
            if flash_cap == 1:
                chip_name = "ESP32-C6FH4 (QFN32)"
            elif flash_cap == 2:
                chip_name = "ESP32-C6FH8 (QFN32)"
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        return f"{chip_name} (revision v{major_rev}.{minor_rev})"

    def get_chip_features(self):
        flash_version = {
            1: "Embedded Flash 4MB",
            2: "Embedded Flash 8MB",
        }.get(self.get_flash_cap(), "Unknown Embedded Flash")

        return [
            "Wi-Fi 6",
            "BT 5 (LE)",
            "IEEE802.15.4",
            "Single Core + LP Core",
            "160MHz",
            flash_version,
        ]

    def get_crystal_freq(self):
        # ESP32C6 XTAL is fixed to 40MHz
        return 40

    def override_vddsdio(self, new_voltage):
        raise NotImplementedInROMError(
            "VDD_SDIO overrides are not supported for ESP32-C6"
        )

    def read_mac(self, mac_type="BASE_MAC"):
        """Read MAC from EFUSE region"""
        mac0 = self.read_reg(self.MAC_EFUSE_REG)
        mac1 = self.read_reg(self.MAC_EFUSE_REG + 4)  # only bottom 16 bits are MAC
        base_mac = struct.pack(">II", mac1, mac0)[2:]
        ext_mac = struct.pack(">H", (mac1 >> 16) & 0xFFFF)
        eui64 = base_mac[0:3] + ext_mac + base_mac[3:6]
        # BASE MAC: 60:55:f9:f7:2c:a2
        # EUI64 MAC: 60:55:f9:ff:fe:f7:2c:a2
        # EXT_MAC: ff:fe
        macs = {
            "BASE_MAC": tuple(base_mac),
            "EUI64": tuple(eui64),
            "MAC_EXT": tuple(ext_mac),
        }
        return macs.get(mac_type, None)

    def get_flash_crypt_config(self):
        return None  # doesn't exist on ESP32-C6

    def get_secure_boot_enabled(self):
        return (
            self.read_reg(self.EFUSE_SECURE_BOOT_EN_REG)
            & self.EFUSE_SECURE_BOOT_EN_MASK
        )

    def get_key_block_purpose(self, key_block):
        if key_block < 0 or key_block > 5:
            raise FatalError("Valid key block numbers must be in range 0-5")

        reg, shift = [
            (self.EFUSE_PURPOSE_KEY0_REG, self.EFUSE_PURPOSE_KEY0_SHIFT),
            (self.EFUSE_PURPOSE_KEY1_REG, self.EFUSE_PURPOSE_KEY1_SHIFT),
            (self.EFUSE_PURPOSE_KEY2_REG, self.EFUSE_PURPOSE_KEY2_SHIFT),
            (self.EFUSE_PURPOSE_KEY3_REG, self.EFUSE_PURPOSE_KEY3_SHIFT),
            (self.EFUSE_PURPOSE_KEY4_REG, self.EFUSE_PURPOSE_KEY4_SHIFT),
            (self.EFUSE_PURPOSE_KEY5_REG, self.EFUSE_PURPOSE_KEY5_SHIFT),
        ][key_block]
        return (self.read_reg(reg) >> shift) & 0xF

    def is_flash_encryption_key_valid(self):
        # Need to see an AES-128 key
        purposes = [self.get_key_block_purpose(b) for b in range(6)]

        return any(p == self.PURPOSE_VAL_XTS_AES128_KEY for p in purposes)

    def check_spi_connection(self, spi_connection):
        if not set(spi_connection).issubset(set(range(0, 31))):
            raise FatalError("SPI Pin numbers must be in the range 0-30.")
        if any([v for v in spi_connection if v in [12, 13]]):
            print(
                "WARNING: GPIO pins 12 and 13 are used by USB-Serial/JTAG, "
                "consider using other pins for SPI flash connection."
            )

    def hard_reset(self):
        # Bug in the USB-Serial/JTAG controller can cause the port to disappear
        # if watchdog reset happens, use standard reset on ESP32-C6
        print('Hard resetting via RTS pin...')
        self._setRTS(True)  # EN->LOW
        time.sleep(0.1)
        self._setRTS(False)


class ESP32C61ROM(ESP32C6ROM):
    CHIP_NAME = "ESP32-C61"
    IMAGE_CHIP_ID = 20

    # ESP32-C61 uses get_chip_id() for detection, not magic value
    CHIP_DETECT_MAGIC_VALUE = []

    UART_DATE_REG_ADDR = 0x60000000 + 0x7C

    EFUSE_BASE = 0x600B4800
    EFUSE_BLOCK1_ADDR = EFUSE_BASE + 0x044
    MAC_EFUSE_REG = EFUSE_BASE + 0x044

    EFUSE_RD_REG_BASE = EFUSE_BASE + 0x030  # BLOCK0 read base address

    EFUSE_PURPOSE_KEY0_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY0_SHIFT = 0
    EFUSE_PURPOSE_KEY1_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY1_SHIFT = 4
    EFUSE_PURPOSE_KEY2_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY2_SHIFT = 8
    EFUSE_PURPOSE_KEY3_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY3_SHIFT = 12
    EFUSE_PURPOSE_KEY4_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY4_SHIFT = 16
    EFUSE_PURPOSE_KEY5_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY5_SHIFT = 20

    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT_REG = EFUSE_RD_REG_BASE
    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT = 1 << 20

    EFUSE_SPI_BOOT_CRYPT_CNT_REG = EFUSE_BASE + 0x030
    EFUSE_SPI_BOOT_CRYPT_CNT_MASK = 0x7 << 23

    EFUSE_SECURE_BOOT_EN_REG = EFUSE_BASE + 0x034
    EFUSE_SECURE_BOOT_EN_MASK = 1 << 26

    # Variable in ROM .bss which indicates the port in use
    @property
    def UARTDEV_BUF_NO(self):
        """Variable .bss.UartDev.buff_uart_no in ROM .bss
        which indicates the port in use.
        """
        return 0x4084F5EC if self.get_chip_revision() <= 2 else 0x4084F5E4

    @property
    def UARTDEV_BUF_NO_USB_JTAG_SERIAL(self):
        """The above var when USB-JTAG/Serial is used."""
        return 3 if self.get_chip_revision() <= 2 else 4

    FLASH_FREQUENCY = {
        "80m": 0xF,
        "40m": 0x0,
        "20m": 0x2,
    }

    MEMORY_MAP = [
        [0x00000000, 0x00010000, "PADDING"],
        [0x42000000, 0x44000000, "DROM"],
        [0x40800000, 0x40860000, "DRAM"],
        [0x40800000, 0x40860000, "BYTE_ACCESSIBLE"],
        [0x4004AC00, 0x40050000, "DROM_MASK"],
        [0x40000000, 0x4004AC00, "IROM_MASK"],
        [0x42000000, 0x44000000, "IROM"],
        [0x40800000, 0x40860000, "IRAM"],
        [0x50000000, 0x50004000, "RTC_IRAM"],
        [0x50000000, 0x50004000, "RTC_DRAM"],
        [0x600FE000, 0x60100000, "MEM_INTERNAL2"],
    ]

    UF2_FAMILY_ID = 0x77D850C4

    KEY_PURPOSES: Dict[int, str] = {
        0: "USER/EMPTY",
        1: "ECDSA_KEY",
        4: "XTS_AES_128_KEY",
        5: "HMAC_DOWN_ALL",
        6: "HMAC_DOWN_JTAG",
        7: "HMAC_DOWN_DIGITAL_SIGNATURE",
        8: "HMAC_UP",
        9: "SECURE_BOOT_DIGEST0",
        10: "SECURE_BOOT_DIGEST1",
        11: "SECURE_BOOT_DIGEST2",
        12: "KM_INIT_KEY",
        15: "XTS_AES_128_KEY_PSRAM",
    }

    def get_pkg_version(self):
        num_word = 2
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 26) & 0x07

    def get_minor_chip_version(self):
        num_word = 2
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 0) & 0x0F

    def get_major_chip_version(self):
        num_word = 2
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 4) & 0x03

    def get_chip_description(self):
        chip_name = {
            0: "ESP32-C61",
        }.get(self.get_pkg_version(), "Unknown ESP32-C61")
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        return f"{chip_name} (revision v{major_rev}.{minor_rev})"

    def get_chip_features(self):
        return ["Wi-Fi 6", "BT 5 (LE)", "Single Core", "160MHz"]

    def read_mac(self, mac_type="BASE_MAC"):
        """Read MAC from EFUSE region"""
        mac0 = self.read_reg(self.MAC_EFUSE_REG)
        mac1 = self.read_reg(self.MAC_EFUSE_REG + 4)  # only bottom 16 bits are MAC
        base_mac = struct.pack(">II", mac1, mac0)[2:]
        # BASE MAC: 60:55:f9:f7:2c:a2
        macs = {
            "BASE_MAC": tuple(base_mac),
        }
        return macs.get(mac_type, None)

    def watchdog_reset(self):
        # Watchdog reset disabled in parent (ESP32-C6) ROM, re-enable it
        ESP32C3ROM.watchdog_reset(self)


class ESP32C5ROM(ESP32C6ROM):
    CHIP_NAME = "ESP32-C5"
    IMAGE_CHIP_ID = 23

    BOOTLOADER_FLASH_OFFSET = 0x2000

    CHIP_DETECT_MAGIC_VALUE = [0x5C501458, 0x5FD1406F, 0x1101406f, 0x63e1406f]

    EFUSE_BASE = 0x600B4800
    EFUSE_BLOCK1_ADDR = EFUSE_BASE + 0x044
    MAC_EFUSE_REG = EFUSE_BASE + 0x044

    EFUSE_RD_REG_BASE = EFUSE_BASE + 0x030  # BLOCK0 read base address

    EFUSE_PURPOSE_KEY0_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY0_SHIFT = 24
    EFUSE_PURPOSE_KEY1_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY1_SHIFT = 28
    EFUSE_PURPOSE_KEY2_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY2_SHIFT = 0
    EFUSE_PURPOSE_KEY3_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY3_SHIFT = 4
    EFUSE_PURPOSE_KEY4_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY4_SHIFT = 8
    EFUSE_PURPOSE_KEY5_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY5_SHIFT = 12

    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT_REG = EFUSE_RD_REG_BASE
    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT = 1 << 20

    EFUSE_SPI_BOOT_CRYPT_CNT_REG = EFUSE_BASE + 0x034
    EFUSE_SPI_BOOT_CRYPT_CNT_MASK = 0x7 << 18

    EFUSE_SECURE_BOOT_EN_REG = EFUSE_BASE + 0x038
    EFUSE_SECURE_BOOT_EN_MASK = 1 << 20

    IROM_MAP_START = 0x42000000
    IROM_MAP_END = 0x44000000
    DROM_MAP_START = 0x42000000
    DROM_MAP_END = 0x44000000

    PCR_SYSCLK_CONF_REG = 0x60096110
    PCR_SYSCLK_XTAL_FREQ_V = 0x7F << 24
    PCR_SYSCLK_XTAL_FREQ_S = 24

    UARTDEV_BUF_NO = 0x4085F51C  # Variable in ROM .bss which indicates the port in use
    UARTDEV_BUF_NO_USB = 3  # The above var when USB-OTG is used
    UARTDEV_BUF_NO_USB_JTAG_SERIAL = 4  # The above var when USB-JTAG/Serial is used

    FLASH_FREQUENCY = {
        "80m": 0xF,
        "40m": 0x0,
        "20m": 0x2,
    }

    MEMORY_MAP = [
        [0x00000000, 0x00010000, "PADDING"],
        [0x42000000, 0x44000000, "DROM"],
        [0x40800000, 0x40860000, "DRAM"],
        [0x40800000, 0x40860000, "BYTE_ACCESSIBLE"],
        [0x4003A000, 0x40040000, "DROM_MASK"],
        [0x40000000, 0x4003A000, "IROM_MASK"],
        [0x42000000, 0x44000000, "IROM"],
        [0x40800000, 0x40860000, "IRAM"],
        [0x50000000, 0x50004000, "RTC_IRAM"],
        [0x50000000, 0x50004000, "RTC_DRAM"],
        [0x600FE000, 0x60100000, "MEM_INTERNAL2"],
    ]

    UF2_FAMILY_ID = 0xF71C0343

    KEY_PURPOSES: dict[int, str] = {
        0: "USER/EMPTY",
        1: "ECDSA_KEY",
        2: "XTS_AES_256_KEY_1",
        3: "XTS_AES_256_KEY_2",
        4: "XTS_AES_128_KEY",
        5: "HMAC_DOWN_ALL",
        6: "HMAC_DOWN_JTAG",
        7: "HMAC_DOWN_DIGITAL_SIGNATURE",
        8: "HMAC_UP",
        9: "SECURE_BOOT_DIGEST0",
        10: "SECURE_BOOT_DIGEST1",
        11: "SECURE_BOOT_DIGEST2",
        12: "KM_INIT_KEY",
    }

    def get_pkg_version(self):
        num_word = 2
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 26) & 0x07

    def get_minor_chip_version(self):
        num_word = 2
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 0) & 0x0F

    def get_major_chip_version(self):
        num_word = 2
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 4) & 0x03

    def get_chip_description(self):
        chip_name = {
            0: "ESP32-C5",
        }.get(self.get_pkg_version(), "Unknown ESP32-C5")
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        return f"{chip_name} (revision v{major_rev}.{minor_rev})"

    def get_chip_features(self):
        return [
            "Wi-Fi 6 (dual-band)",
            "BT 5 (LE)",
            "IEEE802.15.4",
            "Single Core + LP Core",
            "240MHz",
        ]

    def get_crystal_freq(self):
        # The crystal detection algorithm of ESP32/ESP8266
        # works for ESP32-C5 as well.
        return ESPLoader.get_crystal_freq(self)

    def get_crystal_freq_rom_expect(self):
        return (
            self.read_reg(self.PCR_SYSCLK_CONF_REG) & self.PCR_SYSCLK_XTAL_FREQ_V
        ) >> self.PCR_SYSCLK_XTAL_FREQ_S

    def uses_usb(self, _cache=[]):
        if self.secure_download_mode:
            return False  # can't detect native USB in secure download mode
        if not _cache:
            buf_no = self.read_reg(self.UARTDEV_BUF_NO) & 0xff
            _cache.append(buf_no == self.UARTDEV_BUF_NO_USB)
        return _cache[0]

    def uses_usb_jtag_serial(self, _cache=[]):
        """
        Check the UARTDEV_BUF_NO register to see if USB-JTAG/Serial is being used
        """
        if self.secure_download_mode:
            return False  # can't detect USB-JTAG/Serial in secure download mode
        if not _cache:
            buf_no = self.read_reg(self.UARTDEV_BUF_NO) & 0xff
            _cache.append(buf_no == self.UARTDEV_BUF_NO_USB_JTAG_SERIAL)
        return _cache[0]

    def disable_watchdogs(self):
        # When USB-JTAG/Serial is used, the RTC WDT and SWD watchdog are not reset
        # and can then reset the board during flashing. Disable or autofeed them.
        if self.uses_usb_jtag_serial():
            # Disable RTC WDT
            self.write_reg(self.RTC_CNTL_WDTWPROTECT_REG, self.RTC_CNTL_WDT_WKEY)
            self.write_reg(self.RTC_CNTL_WDTCONFIG0_REG, 0)
            self.write_reg(self.RTC_CNTL_WDTWPROTECT_REG, 0)

            # Automatically feed SWD
            self.write_reg(self.RTC_CNTL_SWD_WPROTECT_REG, self.RTC_CNTL_SWD_WKEY)
            self.write_reg(
                self.RTC_CNTL_SWD_CONF_REG,
                self.read_reg(self.RTC_CNTL_SWD_CONF_REG)
                | self.RTC_CNTL_SWD_AUTO_FEED_EN,
            )
            self.write_reg(self.RTC_CNTL_SWD_WPROTECT_REG, 0)

    def _post_connect(self):
        if not self.sync_stub_detected:  # Don't run if stub is reused
            self.disable_watchdogs()

    def check_spi_connection(self, spi_connection):
        if not set(spi_connection).issubset(set(range(0, 29))):
            raise FatalError("SPI Pin numbers must be in the range 0-28.")
        if any([v for v in spi_connection if v in [13, 14]]):
            print(
                "GPIO pins 13 and 14 are used by USB-Serial/JTAG, "
                "consider using other pins for SPI flash connection."
            )

    def rtc_wdt_reset(self):
        print("Hard resetting with RTC WDT...")
        self.write_reg(self.RTC_CNTL_WDTWPROTECT_REG, self.RTC_CNTL_WDT_WKEY)  # unlock
        self.write_reg(self.RTC_CNTL_WDTCONFIG1_REG, 5000)  # set WDT timeout
        self.write_reg(
            self.RTC_CNTL_WDTCONFIG0_REG, (1 << 31) | (5 << 28) | (1 << 8) | 2
        )  # enable WDT
        self.write_reg(self.RTC_CNTL_WDTWPROTECT_REG, 0)  # lock
        time.sleep(0.5)  # wait for reset to take effect

    def hard_reset(self):
        # Use standard reset with USB-JTAG-Serial support
        uses_usb_jtag = self.uses_usb_jtag_serial()
        print('Hard resetting via RTS pin...')
        self._setRTS(True)  # EN->LOW
        if uses_usb_jtag:
            # Give the chip some time to come out of reset, to be able to handle further DTR/RTS transitions
            time.sleep(0.2)
            self._setRTS(False)
            time.sleep(0.2)
        else:
            time.sleep(0.1)
            self._setRTS(False)


class ESP32P4ROM(ESP32ROM):
    CHIP_NAME = "ESP32-P4"
    IMAGE_CHIP_ID = 18

    IROM_MAP_START = 0x40000000
    IROM_MAP_END = 0x4C000000
    DROM_MAP_START = 0x40000000
    DROM_MAP_END = 0x4C000000

    BOOTLOADER_FLASH_OFFSET = 0x2000  # First 2 sectors are reserved for FE purposes

    CHIP_DETECT_MAGIC_VALUE = [0x0, 0x0ADDBAD0]

    UART_DATE_REG_ADDR = 0x500CA000 + 0x8C

    EFUSE_BASE = 0x5012D000
    EFUSE_BLOCK1_ADDR = EFUSE_BASE + 0x044
    MAC_EFUSE_REG = EFUSE_BASE + 0x044

    SPI_REG_BASE = 0x5008D000  # SPIMEM1
    SPI_USR_OFFS = 0x18
    SPI_USR1_OFFS = 0x1C
    SPI_USR2_OFFS = 0x20
    SPI_MOSI_DLEN_OFFS = 0x24
    SPI_MISO_DLEN_OFFS = 0x28
    SPI_W0_OFFS = 0x58

    SPI_ADDR_REG_MSB = False

    USES_MAGIC_VALUE = False

    EFUSE_RD_REG_BASE = EFUSE_BASE + 0x030  # BLOCK0 read base address

    EFUSE_PURPOSE_KEY0_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY0_SHIFT = 24
    EFUSE_PURPOSE_KEY1_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY1_SHIFT = 28
    EFUSE_PURPOSE_KEY2_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY2_SHIFT = 0
    EFUSE_PURPOSE_KEY3_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY3_SHIFT = 4
    EFUSE_PURPOSE_KEY4_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY4_SHIFT = 8
    EFUSE_PURPOSE_KEY5_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY5_SHIFT = 12

    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT_REG = EFUSE_RD_REG_BASE
    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT = 1 << 20

    EFUSE_SPI_BOOT_CRYPT_CNT_REG = EFUSE_BASE + 0x034
    EFUSE_SPI_BOOT_CRYPT_CNT_MASK = 0x7 << 18

    EFUSE_SECURE_BOOT_EN_REG = EFUSE_BASE + 0x038
    EFUSE_SECURE_BOOT_EN_MASK = 1 << 20

    PURPOSE_VAL_XTS_AES256_KEY_1 = 2
    PURPOSE_VAL_XTS_AES256_KEY_2 = 3
    PURPOSE_VAL_XTS_AES128_KEY = 4

    USB_RAM_BLOCK = 0x800  # Max block size USB-OTG is used

    GPIO_STRAP_REG = 0x500E0038
    GPIO_STRAP_SPI_BOOT_MASK = 0x8  # Not download mode
    RTC_CNTL_OPTION1_REG = 0x50110008
    RTC_CNTL_FORCE_DOWNLOAD_BOOT_MASK = 0x4  # Is download mode forced over USB?

    SUPPORTS_ENCRYPTED_FLASH = True

    FLASH_ENCRYPTED_WRITE_ALIGN = 16

    UARTDEV_BUF_NO = 0x4FF3FEC8  # Variable in ROM .bss which indicates the port in use
    UARTDEV_BUF_NO_USB_OTG = 5  # The above var when USB-OTG is used
    UARTDEV_BUF_NO_USB_JTAG_SERIAL = 6  # The above var when USB-JTAG/Serial is used

    MEMORY_MAP = [
        [0x00000000, 0x00010000, "PADDING"],
        [0x40000000, 0x4C000000, "DROM"],
        [0x4FF00000, 0x4FFA0000, "DRAM"],
        [0x4FF00000, 0x4FFA0000, "BYTE_ACCESSIBLE"],
        [0x4FC00000, 0x4FC20000, "DROM_MASK"],
        [0x4FC00000, 0x4FC20000, "IROM_MASK"],
        [0x40000000, 0x4C000000, "IROM"],
        [0x4FF00000, 0x4FFA0000, "IRAM"],
        [0x50108000, 0x50110000, "RTC_IRAM"],
        [0x50108000, 0x50110000, "RTC_DRAM"],
        [0x600FE000, 0x60100000, "MEM_INTERNAL2"],
    ]

    UF2_FAMILY_ID = 0x3D308E94

    KEY_PURPOSES: dict[int, str] = {
        0: "USER/EMPTY",
        1: "ECDSA_KEY",
        2: "XTS_AES_256_KEY_1",
        3: "XTS_AES_256_KEY_2",
        4: "XTS_AES_128_KEY",
        5: "HMAC_DOWN_ALL",
        6: "HMAC_DOWN_JTAG",
        7: "HMAC_DOWN_DIGITAL_SIGNATURE",
        8: "HMAC_UP",
        9: "SECURE_BOOT_DIGEST0",
        10: "SECURE_BOOT_DIGEST1",
        11: "SECURE_BOOT_DIGEST2",
        12: "KM_INIT_KEY",
    }

    DR_REG_LP_WDT_BASE = 0x50116000
    RTC_CNTL_WDTCONFIG0_REG = DR_REG_LP_WDT_BASE + 0x0  # LP_WDT_CONFIG0_REG
    RTC_CNTL_WDTCONFIG1_REG = DR_REG_LP_WDT_BASE + 0x0004  # LP_WDT_CONFIG1_REG
    RTC_CNTL_WDTWPROTECT_REG = DR_REG_LP_WDT_BASE + 0x0018  # LP_WDT_WPROTECT_REG
    RTC_CNTL_WDT_WKEY = 0x50D83AA1

    RTC_CNTL_SWD_CONF_REG = DR_REG_LP_WDT_BASE + 0x001C  # RTC_WDT_SWD_CONFIG_REG
    RTC_CNTL_SWD_AUTO_FEED_EN = 1 << 18
    RTC_CNTL_SWD_WPROTECT_REG = DR_REG_LP_WDT_BASE + 0x0020  # RTC_WDT_SWD_WPROTECT_REG
    RTC_CNTL_SWD_WKEY = 0x50D83AA1  # RTC_WDT_SWD_WKEY, same as WDT key in this case

    def get_pkg_version(self):
        num_word = 2
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 20) & 0x07

    def get_minor_chip_version(self):
        num_word = 2
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 0) & 0x0F

    def get_major_chip_version(self):
        num_word = 2
        word = self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word))
        return (((word >> 23) & 1) << 2) | ((word >> 4) & 0x03)

    def get_chip_description(self):
        chip_name = {
            0: "ESP32-P4",
        }.get(self.get_pkg_version(), "Unknown ESP32-P4")
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        return f"{chip_name} (revision v{major_rev}.{minor_rev})"

    def get_chip_features(self):
        return ["Dual Core + LP Core", "400MHz"]

    def get_chip_full_revision(self):
        return self.get_major_chip_version() * 100 + self.get_minor_chip_version()

    def uses_usb(self, _cache=[]):
        """Check if USB-OTG or USB-JTAG/Serial is being used"""
        if self.secure_download_mode:
            return False  # can't detect native USB in secure download mode
        if not _cache:
            buf_no = self.read_reg(self.UARTDEV_BUF_NO) & 0xff
            _cache.append(buf_no in [self.UARTDEV_BUF_NO_USB_OTG, self.UARTDEV_BUF_NO_USB_JTAG_SERIAL])
        return _cache[0]

    def _post_connect(self):
        # Set USB RAM block if USB is being used
        if self.uses_usb():
            self.ESP_RAM_BLOCK = self.USB_RAM_BLOCK
        
        # ESP32-P4 revision detection: use ESP32P4RC1ROM stub for revisions < 3.0
        if not self.secure_download_mode:
            revision = self.get_chip_full_revision()
            if revision < 300:
                # Use ESP32P4RC1ROM stub code and stub class for revisions below 3.0
                self.STUB_CODE = ESP32P4RC1ROM.STUB_CODE
                self.STUB_CLASS = ESP32P4RC1ROM.STUB_CLASS
                print(f"Detected ESP32-P4 revision {revision // 100}.{revision % 100}, using RC1 stub")

    def get_crystal_freq(self):
        # ESP32P4 XTAL is fixed to 40MHz
        return 40

    def get_flash_voltage(self):
        raise NotSupportedError(self, "Reading flash voltage")

    def override_vddsdio(self, new_voltage):
        raise NotSupportedError(self, "Overriding VDDSDIO")

    def read_mac(self, mac_type="BASE_MAC"):
        """Read MAC from EFUSE region"""
        if mac_type != "BASE_MAC":
            return None
        mac0 = self.read_reg(self.MAC_EFUSE_REG)
        mac1 = self.read_reg(self.MAC_EFUSE_REG + 4)  # only bottom 16 bits are MAC
        bitstring = struct.pack(">II", mac1, mac0)[2:]
        return tuple(bitstring)

    def get_flash_crypt_config(self):
        return None  # doesn't exist on ESP32-P4

    def get_secure_boot_enabled(self):
        return (
            self.read_reg(self.EFUSE_SECURE_BOOT_EN_REG)
            & self.EFUSE_SECURE_BOOT_EN_MASK
        )

    def get_key_block_purpose(self, key_block):
        if key_block < 0 or key_block > self.EFUSE_MAX_KEY:
            raise FatalError(
                f"Valid key block numbers must be in range 0-{self.EFUSE_MAX_KEY}"
            )

        reg, shift = [
            (self.EFUSE_PURPOSE_KEY0_REG, self.EFUSE_PURPOSE_KEY0_SHIFT),
            (self.EFUSE_PURPOSE_KEY1_REG, self.EFUSE_PURPOSE_KEY1_SHIFT),
            (self.EFUSE_PURPOSE_KEY2_REG, self.EFUSE_PURPOSE_KEY2_SHIFT),
            (self.EFUSE_PURPOSE_KEY3_REG, self.EFUSE_PURPOSE_KEY3_SHIFT),
            (self.EFUSE_PURPOSE_KEY4_REG, self.EFUSE_PURPOSE_KEY4_SHIFT),
            (self.EFUSE_PURPOSE_KEY5_REG, self.EFUSE_PURPOSE_KEY5_SHIFT),
        ][key_block]
        return (self.read_reg(reg) >> shift) & 0xF

    def is_flash_encryption_key_valid(self):
        # Need to see either an AES-128 key or two AES-256 keys
        purposes = [
            self.get_key_block_purpose(b) for b in range(self.EFUSE_MAX_KEY + 1)
        ]

        if any(p == self.PURPOSE_VAL_XTS_AES128_KEY for p in purposes):
            return True

        return any(p == self.PURPOSE_VAL_XTS_AES256_KEY_1 for p in purposes) and any(
            p == self.PURPOSE_VAL_XTS_AES256_KEY_2 for p in purposes
        )

    def check_spi_connection(self, spi_connection):
        if not set(spi_connection).issubset(set(range(0, 55))):
            raise FatalError("SPI Pin numbers must be in the range 0-54.")
        if any([v for v in spi_connection if v in [24, 25]]):
            print(
                "GPIO pins 24 and 25 are used by USB-Serial/JTAG, "
                "consider using other pins for SPI flash connection."
            )

    def rtc_wdt_reset(self):
        print("Hard resetting with RTC WDT...")
        self.write_reg(self.RTC_CNTL_WDTWPROTECT_REG, self.RTC_CNTL_WDT_WKEY)  # unlock
        self.write_reg(self.RTC_CNTL_WDTCONFIG1_REG, 5000)  # set WDT timeout
        self.write_reg(
            self.RTC_CNTL_WDTCONFIG0_REG, (1 << 31) | (5 << 28) | (1 << 8) | 2
        )  # enable WDT
        self.write_reg(self.RTC_CNTL_WDTWPROTECT_REG, 0)  # lock
        time.sleep(0.5)  # wait for reset to take effect

    def hard_reset(self):
        if self.uses_usb():
            self.rtc_wdt_reset()
        else:
            print('Hard resetting via RTS pin...')
            self._setRTS(True)  # EN->LOW
            time.sleep(0.1)
            self._setRTS(False)


class ESP32P4RC1ROM(ESP32P4ROM):
    """ESP32-P4 RC1 ROM class for revisions < 3.0"""
    
    def _post_connect(self):
        # Override parent's _post_connect to prevent switching stub code
        # This class already uses the correct RC1 stub code
        pass


class ESP32H2ROM(ESP32C6ROM):
    CHIP_NAME = "ESP32-H2"
    IMAGE_CHIP_ID = 16

    # Magic value for ESP32H2
    CHIP_DETECT_MAGIC_VALUE = [0xD7B73E80]

    DR_REG_LP_WDT_BASE = 0x600B1C00
    RTC_CNTL_WDTCONFIG0_REG = DR_REG_LP_WDT_BASE + 0x0  # LP_WDT_RWDT_CONFIG0_REG
    RTC_CNTL_WDTWPROTECT_REG = DR_REG_LP_WDT_BASE + 0x001C  # LP_WDT_RWDT_WPROTECT_REG

    RTC_CNTL_SWD_CONF_REG = DR_REG_LP_WDT_BASE + 0x0020  # LP_WDT_SWD_CONFIG_REG
    RTC_CNTL_SWD_AUTO_FEED_EN = 1 << 18
    RTC_CNTL_SWD_WPROTECT_REG = DR_REG_LP_WDT_BASE + 0x0024  # LP_WDT_SWD_WPROTECT_REG
    RTC_CNTL_SWD_WKEY = 0x50D83AA1  # LP_WDT_SWD_WKEY, same as WDT key in this case

    FLASH_FREQUENCY = {
        "48m": 0xF,
        "24m": 0x0,
        "16m": 0x1,
        "12m": 0x2,
    }

    UF2_FAMILY_ID = 0x332726F6

    # Returns old version format (ECO number). Use the new format get_chip_full_revision().
    def get_chip_revision(self):
        return self.get_major_chip_version()

    def get_pkg_version(self):
        num_word = 4
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 0) & 0x07

    def get_minor_chip_version(self):
        num_word = 3
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 18) & 0x07

    def get_major_chip_version(self):
        num_word = 3
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 21) & 0x03

    def get_chip_description(self):
        chip_name = {
            0: "ESP32-H2",
        }.get(self.get_pkg_version(), "unknown ESP32-H2")
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        return f"{chip_name} (revision v{major_rev}.{minor_rev})"

    def get_chip_features(self):
        return ["BT 5 (LE)", "IEEE802.15.4", "Single Core", "96MHz"]

    def get_crystal_freq(self):
        # ESP32H2 XTAL is fixed to 32MHz
        return 32



class ESP32C2ROM(ESP32C3ROM):
    CHIP_NAME = "ESP32-C2"
    IMAGE_CHIP_ID = 12

    IROM_MAP_START = 0x42000000
    IROM_MAP_END = 0x42400000
    DROM_MAP_START = 0x3C000000
    DROM_MAP_END = 0x3C400000

    # Magic value for ESP32C2 ECO0 , ECO1 and ECO4 respectively
    CHIP_DETECT_MAGIC_VALUE = [0x6F51306F, 0x7C41A06F, 0x0C21E06F]

    EFUSE_BASE = 0x60008800
    EFUSE_BLOCK2_ADDR = EFUSE_BASE + 0x040
    MAC_EFUSE_REG = EFUSE_BASE + 0x040

    EFUSE_SECURE_BOOT_EN_REG = EFUSE_BASE + 0x30
    EFUSE_SECURE_BOOT_EN_MASK = 1 << 21

    EFUSE_SPI_BOOT_CRYPT_CNT_REG = EFUSE_BASE + 0x30
    EFUSE_SPI_BOOT_CRYPT_CNT_MASK = 0x7 << 18

    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT_REG = EFUSE_BASE + 0x30
    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT = 1 << 6

    EFUSE_XTS_KEY_LENGTH_256_REG = EFUSE_BASE + 0x30
    EFUSE_XTS_KEY_LENGTH_256 = 1 << 10

    EFUSE_BLOCK_KEY0_REG = EFUSE_BASE + 0x60

    EFUSE_RD_DIS_REG = EFUSE_BASE + 0x30
    EFUSE_RD_DIS = 3

    FLASH_FREQUENCY = {
        "60m": 0xF,
        "30m": 0x0,
        "20m": 0x1,
        "15m": 0x2,
    }

    MEMORY_MAP = [
        [0x00000000, 0x00010000, "PADDING"],
        [0x3C000000, 0x3C400000, "DROM"],
        [0x3FCA0000, 0x3FCE0000, "DRAM"],
        [0x3FC88000, 0x3FD00000, "BYTE_ACCESSIBLE"],
        [0x3FF00000, 0x3FF50000, "DROM_MASK"],
        [0x40000000, 0x40090000, "IROM_MASK"],
        [0x42000000, 0x42400000, "IROM"],
        [0x4037C000, 0x403C0000, "IRAM"],
    ]

    UF2_FAMILY_ID = 0x2B88D29C

    # Returns old version format (ECO number). Use the new format get_chip_full_revision().
    def get_chip_revision(self):
        return self.get_major_chip_version()

    def get_pkg_version(self):
        num_word = 1
        return (self.read_reg(self.EFUSE_BLOCK2_ADDR + (4 * num_word)) >> 22) & 0x07

    def get_chip_description(self):
        chip_name = {
            0: "ESP32-C2",
            1: "ESP32-C2",
        }.get(self.get_pkg_version(), "unknown ESP32-C2")
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        return f"{chip_name} (revision v{major_rev}.{minor_rev})"

    def get_chip_features(self):
        features = ["Wi-Fi", "BT 5 (LE)", "Single Core", "120MHz"]

        flash = {
            0: None,
            1: "Embedded Flash 4MB",
            2: "Embedded Flash 2MB",
            3: "Embedded Flash 1MB",
        }.get(self.get_flash_cap(), "Unknown Embedded Flash")
        if flash is not None:
            features += [flash + f" ({self.get_flash_vendor()})"]
        return features

    def get_minor_chip_version(self):
        num_word = 1
        return (self.read_reg(self.EFUSE_BLOCK2_ADDR + (4 * num_word)) >> 16) & 0xF

    def get_major_chip_version(self):
        num_word = 1
        return (self.read_reg(self.EFUSE_BLOCK2_ADDR + (4 * num_word)) >> 20) & 0x3

    def get_flash_cap(self):
        num_word = 7
        return (self.read_reg(self.EFUSE_BLOCK2_ADDR + (4 * num_word)) >> 29) & 0x7

    def get_flash_vendor(self):
        num_word = 7
        vendor_id = (self.read_reg(self.EFUSE_BLOCK2_ADDR + (4 * num_word)) >> 24) & 0x7
        return {1: "XMC", 2: "GD", 3: "FM", 4: "TT", 5: "ZBIT"}.get(vendor_id, "")

    def get_crystal_freq(self):
        # The crystal detection algorithm of ESP32/ESP8266 works for ESP32-C2 as well.
        return ESPLoader.get_crystal_freq(self)

    def change_baud(self, baud):
        rom_with_26M_XTAL = not self.IS_STUB and self.get_crystal_freq() == 26
        if rom_with_26M_XTAL:
            # The code is copied over from ESPLoader.change_baud().
            # Probably this is just a temporary solution until the next chip revision.

            # The ROM code thinks it uses a 40 MHz XTAL. Recompute the baud rate
            # in order to trick the ROM code to set the correct baud rate for
            # a 26 MHz XTAL.
            false_rom_baud = baud * 40 // 26

            print(f"Changing baud rate to {baud}")
            self.command(
                self.ESP_CHANGE_BAUDRATE, struct.pack("<II", false_rom_baud, 0)
            )
            print("Changed.")
            self._set_port_baudrate(baud)
            time.sleep(0.05)  # get rid of garbage sent during baud rate change
            self.flush_input()
        else:
            ESPLoader.change_baud(self, baud)

    def _post_connect(self):
        # ESP32C2 ECO0 is no longer supported by the flasher stub
        if not self.secure_download_mode and self.get_chip_revision() == 0:
            self.stub_is_disabled = True
            self.IS_STUB = False

    """ Try to read (encryption key) and check if it is valid """

    def is_flash_encryption_key_valid(self):
        key_len_256 = (
            self.read_reg(self.EFUSE_XTS_KEY_LENGTH_256_REG)
            & self.EFUSE_XTS_KEY_LENGTH_256
        )

        word0 = self.read_reg(self.EFUSE_RD_DIS_REG) & self.EFUSE_RD_DIS
        rd_disable = word0 == 3 if key_len_256 else word0 == 1

        # reading of BLOCK3 is NOT ALLOWED so we assume valid key is programmed
        if rd_disable:
            return True
        else:
            # reading of BLOCK3 is ALLOWED so we will read and verify for non-zero.
            # When chip has not generated AES/encryption key in BLOCK3,
            # the contents will be readable and 0.
            # If the flash encryption is enabled it is expected to have a valid
            # non-zero key. We break out on first occurance of non-zero value
            key_word = [0] * 7 if key_len_256 else [0] * 3
            for i in range(len(key_word)):
                key_word[i] = self.read_reg(self.EFUSE_BLOCK_KEY0_REG + i * 4)
                # key is non-zero so break & return
                if key_word[i] != 0:
                    return True
            return False



class ESP32StubLoader(ESP32ROM):
    """ Access class for ESP32 stub loader, runs on top of ROM.
    """
    FLASH_WRITE_SIZE = 0x4000  # matches MAX_WRITE_BLOCK in stub_loader.c
    STATUS_BYTES_LENGTH = 2  # same as ESP8266, different to ESP32 ROM
    IS_STUB = True

    def __init__(self, rom_loader):
        self.secure_download_mode = rom_loader.secure_download_mode
        self._port = rom_loader._port
        self._trace_enabled = rom_loader._trace_enabled
        self.flush_input()  # resets _slip_reader


ESP32ROM.STUB_CLASS = ESP32StubLoader


class ESP32S2StubLoader(ESP32S2ROM):
    """ Access class for ESP32-S2 stub loader, runs on top of ROM.

    (Basically the same as ESP32StubLoader, but different base class.
    Can possibly be made into a mixin.)
    """
    FLASH_WRITE_SIZE = 0x4000  # matches MAX_WRITE_BLOCK in stub_loader.c
    STATUS_BYTES_LENGTH = 2  # same as ESP8266, different to ESP32 ROM
    IS_STUB = True

    def __init__(self, rom_loader):
        self.secure_download_mode = rom_loader.secure_download_mode
        self._port = rom_loader._port
        self._trace_enabled = rom_loader._trace_enabled
        self.flush_input()  # resets _slip_reader

        if rom_loader.uses_usb():
            self.ESP_RAM_BLOCK = self.USB_RAM_BLOCK
            self.FLASH_WRITE_SIZE = self.USB_RAM_BLOCK


ESP32S2ROM.STUB_CLASS = ESP32S2StubLoader


class ESP32S3StubLoader(ESP32S3ROM):
    """ Access class for ESP32S3 stub loader, runs on top of ROM.

    (Basically the same as ESP32StubLoader, but different base class.
    Can possibly be made into a mixin.)
    """
    FLASH_WRITE_SIZE = 0x4000  # matches MAX_WRITE_BLOCK in stub_loader.c
    STATUS_BYTES_LENGTH = 2  # same as ESP8266, different to ESP32 ROM
    IS_STUB = True

    def __init__(self, rom_loader):
        self.secure_download_mode = rom_loader.secure_download_mode
        self._port = rom_loader._port
        self._trace_enabled = rom_loader._trace_enabled
        self.flush_input()  # resets _slip_reader

        if rom_loader.uses_usb():
            self.ESP_RAM_BLOCK = self.USB_RAM_BLOCK
            self.FLASH_WRITE_SIZE = self.USB_RAM_BLOCK


ESP32S3ROM.STUB_CLASS = ESP32S3StubLoader


class ESP32C3StubLoader(ESP32C3ROM):
    """ Access class for ESP32C3 stub loader, runs on top of ROM.

    (Basically the same as ESP32StubLoader, but different base class.
    Can possibly be made into a mixin.)
    """
    FLASH_WRITE_SIZE = 0x4000  # matches MAX_WRITE_BLOCK in stub_loader.c
    STATUS_BYTES_LENGTH = 2  # same as ESP8266, different to ESP32 ROM
    IS_STUB = True

    def __init__(self, rom_loader):
        self.secure_download_mode = rom_loader.secure_download_mode
        self._port = rom_loader._port
        self._trace_enabled = rom_loader._trace_enabled
        self.flush_input()  # resets _slip_reader


ESP32C3ROM.STUB_CLASS = ESP32C3StubLoader


class ESP32C5StubLoader(ESP32C5ROM):
    """Access class for ESP32C5 stub loader, runs on top of ROM.

    (Basically the same as ESP32StubLoader, but different base class.
    Can possibly be made into a mixin.)
    """

    FLASH_WRITE_SIZE = 0x4000  # matches MAX_WRITE_BLOCK in stub_loader.c
    STATUS_BYTES_LENGTH = 2  # same as ESP8266, different to ESP32 ROM
    IS_STUB = True

    def __init__(self, rom_loader):
        self.secure_download_mode = rom_loader.secure_download_mode
        self._port = rom_loader._port
        self._trace_enabled = rom_loader._trace_enabled
        self.flush_input()  # resets _slip_reader


ESP32C5ROM.STUB_CLASS = ESP32C5StubLoader


class ESP32C6StubLoader(ESP32C6ROM):
    """Access class for ESP32C6 stub loader, runs on top of ROM.

    (Basically the same as ESP32StubLoader, but different base class.
    Can possibly be made into a mixin.)
    """

    FLASH_WRITE_SIZE = 0x4000  # matches MAX_WRITE_BLOCK in stub_loader.c
    STATUS_BYTES_LENGTH = 2  # same as ESP8266, different to ESP32 ROM
    IS_STUB = True

    def __init__(self, rom_loader):
        self.secure_download_mode = rom_loader.secure_download_mode
        self._port = rom_loader._port
        self._trace_enabled = rom_loader._trace_enabled
        self.flush_input()  # resets _slip_reader


ESP32C6ROM.STUB_CLASS = ESP32C6StubLoader


class ESP32C61StubLoader(ESP32C61ROM):
    """Access class for ESP32C61 stub loader, runs on top of ROM.

    (Basically the same as ESP32StubLoader, but different base class.
    Can possibly be made into a mixin.)
    """

    FLASH_WRITE_SIZE = 0x4000  # matches MAX_WRITE_BLOCK in stub_loader.c
    STATUS_BYTES_LENGTH = 2  # same as ESP8266, different to ESP32 ROM
    IS_STUB = True

    def __init__(self, rom_loader):
        self.secure_download_mode = rom_loader.secure_download_mode
        self._port = rom_loader._port
        self._trace_enabled = rom_loader._trace_enabled
        self.flush_input()  # resets _slip_reader


ESP32C61ROM.STUB_CLASS = ESP32C61StubLoader


class ESP32P4StubLoader(ESP32P4ROM):
    """Access class for ESP32P4 stub loader, runs on top of ROM.

    (Basically the same as ESP32StubLoader, but different base class.
    Can possibly be made into a mixin.)
    """

    FLASH_WRITE_SIZE = 0x4000  # matches MAX_WRITE_BLOCK in stub_loader.c
    STATUS_BYTES_LENGTH = 2  # same as ESP8266, different to ESP32 ROM
    IS_STUB = True

    def __init__(self, rom_loader):
        self.secure_download_mode = rom_loader.secure_download_mode
        self._port = rom_loader._port
        self._trace_enabled = rom_loader._trace_enabled
        self.flush_input()  # resets _slip_reader
        
        # Cache USB status from ROM loader
        self._uses_usb = rom_loader.uses_usb()
        if self._uses_usb:
            self.ESP_RAM_BLOCK = self.USB_RAM_BLOCK
    
    def uses_usb(self):
        return self._uses_usb


ESP32P4ROM.STUB_CLASS = ESP32P4StubLoader


class ESP32P4RC1StubLoader(ESP32P4RC1ROM):
    """Access class for ESP32P4 RC1 stub loader, runs on top of ROM."""

    FLASH_WRITE_SIZE = 0x4000  # matches MAX_WRITE_BLOCK in stub_loader.c
    STATUS_BYTES_LENGTH = 2  # same as ESP8266, different to ESP32 ROM
    IS_STUB = True

    def __init__(self, rom_loader):
        self.secure_download_mode = rom_loader.secure_download_mode
        self._port = rom_loader._port
        self._trace_enabled = rom_loader._trace_enabled
        self.flush_input()  # resets _slip_reader
        
        # Cache USB status from ROM loader
        self._uses_usb = rom_loader.uses_usb()
        if self._uses_usb:
            self.ESP_RAM_BLOCK = self.USB_RAM_BLOCK
    
    def uses_usb(self):
        return self._uses_usb


ESP32P4RC1ROM.STUB_CLASS = ESP32P4RC1StubLoader


class ESP32H2StubLoader(ESP32H2ROM):
    """Access class for ESP32H2 stub loader, runs on top of ROM.

    (Basically the same as ESP32StubLoader, but different base class.
    Can possibly be made into a mixin.)
    """

    FLASH_WRITE_SIZE = 0x4000  # matches MAX_WRITE_BLOCK in stub_loader.c
    STATUS_BYTES_LENGTH = 2  # same as ESP8266, different to ESP32 ROM
    IS_STUB = True

    def __init__(self, rom_loader):
        self.secure_download_mode = rom_loader.secure_download_mode
        self._port = rom_loader._port
        self._trace_enabled = rom_loader._trace_enabled
        self.flush_input()  # resets _slip_reader


ESP32H2ROM.STUB_CLASS = ESP32H2StubLoader


class ESP32C2StubLoader(ESP32C2ROM):
    """Access class for ESP32C2 stub loader, runs on top of ROM.

    (Basically the same as ESP32StubLoader, but different base class.
    Can possibly be made into a mixin.)
    """

    FLASH_WRITE_SIZE = 0x4000  # matches MAX_WRITE_BLOCK in stub_loader.c
    STATUS_BYTES_LENGTH = 2  # same as ESP8266, different to ESP32 ROM
    IS_STUB = True

    def __init__(self, rom_loader):
        self.secure_download_mode = rom_loader.secure_download_mode
        self._port = rom_loader._port
        self._trace_enabled = rom_loader._trace_enabled
        self.flush_input()  # resets _slip_reader


ESP32C2ROM.STUB_CLASS = ESP32C2StubLoader


class ESPBOOTLOADER(object):
    """ These are constants related to software ESP8266 bootloader, working with 'v2' image files """

    # First byte of the "v2" application image
    IMAGE_V2_MAGIC = 0xea

    # First 'segment' value in a "v2" application image, appears to be a constant version value?
    IMAGE_V2_SEGMENT = 4


def LoadFirmwareImage(chip, filename):
    """ Load a firmware image. Can be for any supported SoC.

        ESP8266 images will be examined to determine if they are original ROM firmware images (ESP8266ROMFirmwareImage)
        or "v2" OTA bootloader images.

        Returns a BaseFirmwareImage subclass, either ESP8266ROMFirmwareImage (v1) or ESP8266V2FirmwareImage (v2).
    """
    chip = re.sub(r"[-()]", "", chip.lower())
    with open(filename, 'rb') as f:
        if chip == 'esp32':
            return ESP32FirmwareImage(f)
        elif chip == "esp32s2":
            return ESP32S2FirmwareImage(f)
        elif chip == "esp32s3":
            return ESP32S3FirmwareImage(f)
        elif chip == 'esp32c3':
            return ESP32C3FirmwareImage(f)
        elif chip == 'esp32c5':
            return ESP32C5FirmwareImage(f)
        elif chip == 'esp32c6':
            return ESP32C6FirmwareImage(f)
        elif chip == 'esp32h2':
            return ESP32H2FirmwareImage(f)
        elif chip == 'esp32c2':
            return ESP32C2FirmwareImage(f)
        elif chip == 'esp32p4':
            return ESP32P4FirmwareImage(f)
        else:  # Otherwise, ESP8266 so look at magic to determine the image type
            magic = ord(f.read(1))
            f.seek(0)
            if magic == ESPLoader.ESP_IMAGE_MAGIC:
                return ESP8266ROMFirmwareImage(f)
            elif magic == ESPBOOTLOADER.IMAGE_V2_MAGIC:
                return ESP8266V2FirmwareImage(f)
            else:
                raise FatalError("Invalid image magic number: %d" % magic)


class ImageSegment(object):
    """ Wrapper class for a segment in an ESP image
    (very similar to a section in an ELFImage also) """
    def __init__(self, addr, data, file_offs=None):
        self.addr = addr
        self.data = data
        self.file_offs = file_offs
        self.include_in_checksum = True
        if self.addr != 0:
            self.pad_to_alignment(4)  # pad all "real" ImageSegments 4 byte aligned length

    def copy_with_new_addr(self, new_addr):
        """ Return a new ImageSegment with same data, but mapped at
        a new address. """
        return ImageSegment(new_addr, self.data, 0)

    def split_image(self, split_len):
        """ Return a new ImageSegment which splits "split_len" bytes
        from the beginning of the data. Remaining bytes are kept in
        this segment object (and the start address is adjusted to match.) """
        result = copy.copy(self)
        result.data = self.data[:split_len]
        self.data = self.data[split_len:]
        self.addr += split_len
        self.file_offs = None
        result.file_offs = None
        return result

    def __repr__(self):
        r = "len 0x%05x load 0x%08x" % (len(self.data), self.addr)
        if self.file_offs is not None:
            r += " file_offs 0x%08x" % (self.file_offs)
        return r

    def get_memory_type(self, image):
        """
        Return a list describing the memory type(s) that is covered by this
        segment's start address.
        """
        return [map_range[2] for map_range in image.ROM_LOADER.MEMORY_MAP if map_range[0] <= self.addr < map_range[1]]

    def pad_to_alignment(self, alignment):
        self.data = pad_to(self.data, alignment, b'\x00')


class ELFSection(ImageSegment):
    """ Wrapper class for a section in an ELF image, has a section
    name as well as the common properties of an ImageSegment. """
    def __init__(self, name, addr, data):
        super(ELFSection, self).__init__(addr, data)
        self.name = name.decode("utf-8")

    def __repr__(self):
        return "%s %s" % (self.name, super(ELFSection, self).__repr__())


class BaseFirmwareImage(object):
    SEG_HEADER_LEN = 8
    SHA256_DIGEST_LEN = 32

    """ Base class with common firmware image functions """
    def __init__(self):
        self.segments = []
        self.entrypoint = 0
        self.elf_sha256 = None
        self.elf_sha256_offset = 0
        self.pad_to_size = 0

    def load_common_header(self, load_file, expected_magic):
        (magic, segments, self.flash_mode, self.flash_size_freq, self.entrypoint) = struct.unpack('<BBBBI', load_file.read(8))

        if magic != expected_magic:
            raise FatalError('Invalid firmware image magic=0x%x' % (magic))
        return segments

    def verify(self):
        if len(self.segments) > 16:
            raise FatalError('Invalid segment count %d (max 16). Usually this indicates a linker script problem.' % len(self.segments))

    def load_segment(self, f, is_irom_segment=False):
        """ Load the next segment from the image file """
        file_offs = f.tell()
        (offset, size) = struct.unpack('<II', f.read(8))
        self.warn_if_unusual_segment(offset, size, is_irom_segment)
        segment_data = f.read(size)
        if len(segment_data) < size:
            raise FatalError('End of file reading segment 0x%x, length %d (actual length %d)' % (offset, size, len(segment_data)))
        segment = ImageSegment(offset, segment_data, file_offs)
        self.segments.append(segment)
        return segment

    def warn_if_unusual_segment(self, offset, size, is_irom_segment):
        if not is_irom_segment:
            if offset > 0x40200000 or offset < 0x3ffe0000 or size > 65536:
                print('WARNING: Suspicious segment 0x%x, length %d' % (offset, size))

    def maybe_patch_segment_data(self, f, segment_data):
        """If SHA256 digest of the ELF file needs to be inserted into this segment, do so. Returns segment data."""
        segment_len = len(segment_data)
        file_pos = f.tell()  # file_pos is position in the .bin file
        if self.elf_sha256_offset >= file_pos and self.elf_sha256_offset < file_pos + segment_len:
            # SHA256 digest needs to be patched into this binary segment,
            # calculate offset of the digest inside the binary segment.
            patch_offset = self.elf_sha256_offset - file_pos
            # Sanity checks
            if patch_offset < self.SEG_HEADER_LEN or patch_offset + self.SHA256_DIGEST_LEN > segment_len:
                raise FatalError('Cannot place SHA256 digest on segment boundary'
                                 '(elf_sha256_offset=%d, file_pos=%d, segment_size=%d)' %
                                 (self.elf_sha256_offset, file_pos, segment_len))
            # offset relative to the data part
            patch_offset -= self.SEG_HEADER_LEN
            if segment_data[patch_offset:patch_offset + self.SHA256_DIGEST_LEN] != b'\x00' * self.SHA256_DIGEST_LEN:
                raise FatalError('Contents of segment at SHA256 digest offset 0x%x are not all zero. Refusing to overwrite.' %
                                 self.elf_sha256_offset)
            assert len(self.elf_sha256) == self.SHA256_DIGEST_LEN
            segment_data = segment_data[0:patch_offset] + self.elf_sha256 + \
                segment_data[patch_offset + self.SHA256_DIGEST_LEN:]
        return segment_data

    def save_segment(self, f, segment, checksum=None):
        """ Save the next segment to the image file, return next checksum value if provided """
        segment_data = self.maybe_patch_segment_data(f, segment.data)
        f.write(struct.pack('<II', segment.addr, len(segment_data)))
        f.write(segment_data)
        if checksum is not None:
            return ESPLoader.checksum(segment_data, checksum)

    def save_flash_segment(self, f, segment, checksum=None):
        """
        Save the next segment to the image file, return next checksum value if provided
        """
        if self.ROM_LOADER.CHIP_NAME == "ESP32":
            # Work around a bug in ESP-IDF 2nd stage bootloader, that it didn't map the
            # last MMU page, if an IROM/DROM segment was < 0x24 bytes
            # over the page boundary.
            segment_end_pos = f.tell() + len(segment.data) + self.SEG_HEADER_LEN
            segment_len_remainder = segment_end_pos % self.IROM_ALIGN
            if segment_len_remainder < 0x24:
                segment.data += b"\x00" * (0x24 - segment_len_remainder)
        return self.save_segment(f, segment, checksum)

    def read_checksum(self, f):
        """ Return ESPLoader checksum from end of just-read image """
        # Skip the padding. The checksum is stored in the last byte so that the
        # file is a multiple of 16 bytes.
        align_file_position(f, 16)
        return ord(f.read(1))

    def calculate_checksum(self):
        """ Calculate checksum of loaded image, based on segments in
        segment array.
        """
        checksum = ESPLoader.ESP_CHECKSUM_MAGIC
        for seg in self.segments:
            if seg.include_in_checksum:
                checksum = ESPLoader.checksum(seg.data, checksum)
        return checksum

    def append_checksum(self, f, checksum):
        """ Append ESPLoader checksum to the just-written image """
        align_file_position(f, 16)
        f.write(struct.pack(b'B', checksum))

    def write_common_header(self, f, segments):
        f.write(struct.pack('<BBBBI', ESPLoader.ESP_IMAGE_MAGIC, len(segments),
                            self.flash_mode, self.flash_size_freq, self.entrypoint))

    def is_irom_addr(self, addr):
        """ Returns True if an address starts in the irom region.
        Valid for ESP8266 only.
        """
        return ESP8266ROM.IROM_MAP_START <= addr < ESP8266ROM.IROM_MAP_END

    def get_irom_segment(self):
        irom_segments = [s for s in self.segments if self.is_irom_addr(s.addr)]
        if len(irom_segments) > 0:
            if len(irom_segments) != 1:
                raise FatalError('Found %d segments that could be irom0. Bad ELF file?' % len(irom_segments))
            return irom_segments[0]
        return None

    def get_non_irom_segments(self):
        irom_segment = self.get_irom_segment()
        return [s for s in self.segments if s != irom_segment]

    def merge_adjacent_segments(self):
        if not self.segments:
            return  # nothing to merge

        segments = []
        # The easiest way to merge the sections is the browse them backward.
        for i in range(len(self.segments) - 1, 0, -1):
            # elem is the previous section, the one `next_elem` may need to be
            # merged in
            elem = self.segments[i - 1]
            next_elem = self.segments[i]
            if all((elem.get_memory_type(self) == next_elem.get_memory_type(self),
                    elem.include_in_checksum == next_elem.include_in_checksum,
                    next_elem.addr == elem.addr + len(elem.data))):
                # Merge any segment that ends where the next one starts, without spanning memory types
                #
                # (don't 'pad' any gaps here as they may be excluded from the image due to 'noinit'
                # or other reasons.)
                elem.data += next_elem.data
            else:
                # The section next_elem cannot be merged into the previous one,
                # which means it needs to be part of the final segments.
                # As we are browsing the list backward, the elements need to be
                # inserted at the beginning of the final list.
                segments.insert(0, next_elem)

        # The first segment will always be here as it cannot be merged into any
        # "previous" section.
        segments.insert(0, self.segments[0])

        # note: we could sort segments here as well, but the ordering of segments is sometimes
        # important for other reasons (like embedded ELF SHA-256), so we assume that the linker
        # script will have produced any adjacent sections in linear order in the ELF, anyhow.
        self.segments = segments

    def set_mmu_page_size(self, size):
        """ If supported, this should be overridden by the chip-specific class. Gets called in elf2image. """
        print('WARNING: Changing MMU page size is not supported on {}! Defaulting to 64KB.'.format(self.ROM_LOADER.CHIP_NAME))


class ESP8266ROMFirmwareImage(BaseFirmwareImage):
    """ 'Version 1' firmware image, segments loaded directly by the ROM bootloader. """

    ROM_LOADER = ESP8266ROM

    def __init__(self, load_file=None):
        super(ESP8266ROMFirmwareImage, self).__init__()
        self.flash_mode = 0
        self.flash_size_freq = 0
        self.version = 1

        if load_file is not None:
            segments = self.load_common_header(load_file, ESPLoader.ESP_IMAGE_MAGIC)

            for _ in range(segments):
                self.load_segment(load_file)
            self.checksum = self.read_checksum(load_file)

            self.verify()

    def default_output_name(self, input_file):
        """ Derive a default output name from the ELF name. """
        return input_file + '-'

    def save(self, basename):
        """ Save a set of V1 images for flashing. Parameter is a base filename. """
        # IROM data goes in its own plain binary file
        irom_segment = self.get_irom_segment()
        if irom_segment is not None:
            with open("%s0x%05x.bin" % (basename, irom_segment.addr - ESP8266ROM.IROM_MAP_START), "wb") as f:
                f.write(irom_segment.data)

        # everything but IROM goes at 0x00000 in an image file
        normal_segments = self.get_non_irom_segments()
        with open("%s0x00000.bin" % basename, 'wb') as f:
            self.write_common_header(f, normal_segments)
            checksum = ESPLoader.ESP_CHECKSUM_MAGIC
            for segment in normal_segments:
                checksum = self.save_segment(f, segment, checksum)
            self.append_checksum(f, checksum)


ESP8266ROM.BOOTLOADER_IMAGE = ESP8266ROMFirmwareImage


class ESP8266V2FirmwareImage(BaseFirmwareImage):
    """ 'Version 2' firmware image, segments loaded by software bootloader stub
        (ie Espressif bootloader or rboot)
    """

    ROM_LOADER = ESP8266ROM

    def __init__(self, load_file=None):
        super(ESP8266V2FirmwareImage, self).__init__()
        self.version = 2
        if load_file is not None:
            segments = self.load_common_header(load_file, ESPBOOTLOADER.IMAGE_V2_MAGIC)
            if segments != ESPBOOTLOADER.IMAGE_V2_SEGMENT:
                # segment count is not really segment count here, but we expect to see '4'
                print('Warning: V2 header has unexpected "segment" count %d (usually 4)' % segments)

            # irom segment comes before the second header
            #
            # the file is saved in the image with a zero load address
            # in the header, so we need to calculate a load address
            irom_segment = self.load_segment(load_file, True)
            irom_segment.addr = 0  # for actual mapped addr, add ESP8266ROM.IROM_MAP_START + flashing_addr + 8
            irom_segment.include_in_checksum = False

            first_flash_mode = self.flash_mode
            first_flash_size_freq = self.flash_size_freq
            first_entrypoint = self.entrypoint
            # load the second header

            segments = self.load_common_header(load_file, ESPLoader.ESP_IMAGE_MAGIC)

            if first_flash_mode != self.flash_mode:
                print('WARNING: Flash mode value in first header (0x%02x) disagrees with second (0x%02x). Using second value.'
                      % (first_flash_mode, self.flash_mode))
            if first_flash_size_freq != self.flash_size_freq:
                print('WARNING: Flash size/freq value in first header (0x%02x) disagrees with second (0x%02x). Using second value.'
                      % (first_flash_size_freq, self.flash_size_freq))
            if first_entrypoint != self.entrypoint:
                print('WARNING: Entrypoint address in first header (0x%08x) disagrees with second header (0x%08x). Using second value.'
                      % (first_entrypoint, self.entrypoint))

            # load all the usual segments
            for _ in range(segments):
                self.load_segment(load_file)
            self.checksum = self.read_checksum(load_file)

            self.verify()

    def default_output_name(self, input_file):
        """ Derive a default output name from the ELF name. """
        irom_segment = self.get_irom_segment()
        if irom_segment is not None:
            irom_offs = irom_segment.addr - ESP8266ROM.IROM_MAP_START
        else:
            irom_offs = 0
        return "%s-0x%05x.bin" % (os.path.splitext(input_file)[0],
                                  irom_offs & ~(ESPLoader.FLASH_SECTOR_SIZE - 1))

    def save(self, filename):
        with open(filename, 'wb') as f:
            # Save first header for irom0 segment
            f.write(struct.pack(b'<BBBBI', ESPBOOTLOADER.IMAGE_V2_MAGIC, ESPBOOTLOADER.IMAGE_V2_SEGMENT,
                                self.flash_mode, self.flash_size_freq, self.entrypoint))

            irom_segment = self.get_irom_segment()
            if irom_segment is not None:
                # save irom0 segment, make sure it has load addr 0 in the file
                irom_segment = irom_segment.copy_with_new_addr(0)
                irom_segment.pad_to_alignment(16)  # irom_segment must end on a 16 byte boundary
                self.save_segment(f, irom_segment)

            # second header, matches V1 header and contains loadable segments
            normal_segments = self.get_non_irom_segments()
            self.write_common_header(f, normal_segments)
            checksum = ESPLoader.ESP_CHECKSUM_MAGIC
            for segment in normal_segments:
                checksum = self.save_segment(f, segment, checksum)
            self.append_checksum(f, checksum)

        # calculate a crc32 of entire file and append
        # (algorithm used by recent 8266 SDK bootloaders)
        with open(filename, 'rb') as f:
            crc = esp8266_crc32(f.read())
        with open(filename, 'ab') as f:
            f.write(struct.pack(b'<I', crc))


def esp8266_crc32(data):
    """
    CRC32 algorithm used by 8266 SDK bootloader (and gen_appbin.py).
    """
    crc = binascii.crc32(data, 0) & 0xFFFFFFFF
    if crc & 0x80000000:
        return crc ^ 0xFFFFFFFF
    else:
        return crc + 1


class ESP32FirmwareImage(BaseFirmwareImage):
    """ ESP32 firmware image is very similar to V1 ESP8266 image,
    except with an additional 16 byte reserved header at top of image,
    and because of new flash mapping capabilities the flash-mapped regions
    can be placed in the normal image (just @ 64kB padded offsets).
    """

    ROM_LOADER = ESP32ROM

    # ROM bootloader will read the wp_pin field if SPI flash
    # pins are remapped via flash. IDF actually enables QIO only
    # from software bootloader, so this can be ignored. But needs
    # to be set to this value so ROM bootloader will skip it.
    WP_PIN_DISABLED = 0xEE

    EXTENDED_HEADER_STRUCT_FMT = "<BBBBHBHH" + ("B" * 4) + "B"

    IROM_ALIGN = 65536

    def __init__(self, load_file=None):
        super(ESP32FirmwareImage, self).__init__()
        self.secure_pad = None
        self.flash_mode = 0
        self.flash_size_freq = 0
        self.version = 1
        self.wp_pin = self.WP_PIN_DISABLED
        # SPI pin drive levels
        self.clk_drv = 0
        self.q_drv = 0
        self.d_drv = 0
        self.cs_drv = 0
        self.hd_drv = 0
        self.wp_drv = 0
        self.min_rev = 0
        self.min_rev_full = 0
        self.max_rev_full = 0

        self.append_digest = True

        if load_file is not None:
            start = load_file.tell()

            segments = self.load_common_header(load_file, ESPLoader.ESP_IMAGE_MAGIC)
            self.load_extended_header(load_file)

            for _ in range(segments):
                self.load_segment(load_file)
            self.checksum = self.read_checksum(load_file)

            if self.append_digest:
                end = load_file.tell()
                self.stored_digest = load_file.read(32)
                load_file.seek(start)
                calc_digest = hashlib.sha256()
                calc_digest.update(load_file.read(end - start))
                self.calc_digest = calc_digest.digest()  # TODO: decide what to do here?

            self.verify()

    def is_flash_addr(self, addr):
        return (self.ROM_LOADER.IROM_MAP_START <= addr < self.ROM_LOADER.IROM_MAP_END) \
            or (self.ROM_LOADER.DROM_MAP_START <= addr < self.ROM_LOADER.DROM_MAP_END)

    def default_output_name(self, input_file):
        """ Derive a default output name from the ELF name. """
        return "%s.bin" % (os.path.splitext(input_file)[0])

    def warn_if_unusual_segment(self, offset, size, is_irom_segment):
        pass  # TODO: add warnings for ESP32 segment offset/size combinations that are wrong

    def save(self, filename):
        total_segments = 0
        with io.BytesIO() as f:  # write file to memory first
            self.write_common_header(f, self.segments)

            # first 4 bytes of header are read by ROM bootloader for SPI
            # config, but currently unused
            self.save_extended_header(f)

            checksum = ESPLoader.ESP_CHECKSUM_MAGIC

            # split segments into flash-mapped vs ram-loaded, and take copies so we can mutate them
            flash_segments = [copy.deepcopy(s) for s in sorted(self.segments, key=lambda s:s.addr) if self.is_flash_addr(s.addr)]
            ram_segments = [copy.deepcopy(s) for s in sorted(self.segments, key=lambda s:s.addr) if not self.is_flash_addr(s.addr)]

            # check for multiple ELF sections that are mapped in the same flash mapping region.
            # this is usually a sign of a broken linker script, but if you have a legitimate
            # use case then let us know
            if len(flash_segments) > 0:
                last_addr = flash_segments[0].addr
                for segment in flash_segments[1:]:
                    if segment.addr // self.IROM_ALIGN == last_addr // self.IROM_ALIGN:
                        raise FatalError(("Segment loaded at 0x%08x lands in same 64KB flash mapping as segment loaded at 0x%08x. "
                                          "Can't generate binary. Suggest changing linker script or ELF to merge sections.") %
                                         (segment.addr, last_addr))
                    last_addr = segment.addr

            def get_alignment_data_needed(segment):
                # Actual alignment (in data bytes) required for a segment header: positioned so that
                # after we write the next 8 byte header, file_offs % IROM_ALIGN == segment.addr % IROM_ALIGN
                #
                # (this is because the segment's vaddr may not be IROM_ALIGNed, more likely is aligned
                # IROM_ALIGN+0x18 to account for the binary file header
                align_past = (segment.addr % self.IROM_ALIGN) - self.SEG_HEADER_LEN
                pad_len = (self.IROM_ALIGN - (f.tell() % self.IROM_ALIGN)) + align_past
                if pad_len == 0 or pad_len == self.IROM_ALIGN:
                    return 0  # already aligned

                # subtract SEG_HEADER_LEN a second time, as the padding block has a header as well
                pad_len -= self.SEG_HEADER_LEN
                if pad_len < 0:
                    pad_len += self.IROM_ALIGN
                return pad_len

            # try to fit each flash segment on a 64kB aligned boundary
            # by padding with parts of the non-flash segments...
            while len(flash_segments) > 0:
                segment = flash_segments[0]
                pad_len = get_alignment_data_needed(segment)
                if pad_len > 0:  # need to pad
                    if len(ram_segments) > 0 and pad_len > self.SEG_HEADER_LEN:
                        pad_segment = ram_segments[0].split_image(pad_len)
                        if len(ram_segments[0].data) == 0:
                            ram_segments.pop(0)
                    else:
                        pad_segment = ImageSegment(0, b'\x00' * pad_len, f.tell())
                    checksum = self.save_segment(f, pad_segment, checksum)
                    total_segments += 1
                else:
                    # write the flash segment
                    assert (f.tell() + 8) % self.IROM_ALIGN == segment.addr % self.IROM_ALIGN
                    checksum = self.save_flash_segment(f, segment, checksum)
                    flash_segments.pop(0)
                    total_segments += 1

            # flash segments all written, so write any remaining RAM segments
            for segment in ram_segments:
                checksum = self.save_segment(f, segment, checksum)
                total_segments += 1

            if self.secure_pad:
                # pad the image so that after signing it will end on a a 64KB boundary.
                # This ensures all mapped flash content will be verified.
                if not self.append_digest:
                    raise FatalError("secure_pad only applies if a SHA-256 digest is also appended to the image")
                align_past = (f.tell() + self.SEG_HEADER_LEN) % self.IROM_ALIGN
                # 16 byte aligned checksum (force the alignment to simplify calculations)
                checksum_space = 16
                if self.secure_pad == '1':
                    # after checksum: SHA-256 digest + (to be added by signing process) version, signature + 12 trailing bytes due to alignment
                    space_after_checksum = 32 + 4 + 64 + 12
                elif self.secure_pad == '2':  # Secure Boot V2
                    # after checksum: SHA-256 digest + signature sector, but we place signature sector after the 64KB boundary
                    space_after_checksum = 32
                pad_len = (self.IROM_ALIGN - align_past - checksum_space - space_after_checksum) % self.IROM_ALIGN
                pad_segment = ImageSegment(0, b'\x00' * pad_len, f.tell())

                checksum = self.save_segment(f, pad_segment, checksum)
                total_segments += 1

            # done writing segments
            self.append_checksum(f, checksum)
            image_length = f.tell()

            if self.secure_pad:
                assert ((image_length + space_after_checksum) % self.IROM_ALIGN) == 0

            # kinda hacky: go back to the initial header and write the new segment count
            # that includes padding segments. This header is not checksummed
            f.seek(1)
            try:
                f.write(chr(total_segments))
            except TypeError:  # Python 3
                f.write(bytes([total_segments]))

            if self.append_digest:
                # calculate the SHA256 of the whole file and append it
                f.seek(0)
                digest = hashlib.sha256()
                digest.update(f.read(image_length))
                f.write(digest.digest())

            if self.pad_to_size:
                image_length = f.tell()
                if image_length % self.pad_to_size != 0:
                    pad_by = self.pad_to_size - (image_length % self.pad_to_size)
                    f.write(b"\xff" * pad_by)

            with open(filename, 'wb') as real_file:
                real_file.write(f.getvalue())

    def load_extended_header(self, load_file):
        def split_byte(n):
            return (n & 0x0F, (n >> 4) & 0x0F)

        fields = list(struct.unpack(self.EXTENDED_HEADER_STRUCT_FMT, load_file.read(16)))

        self.wp_pin = fields[0]

        # SPI pin drive stengths are two per byte
        self.clk_drv, self.q_drv = split_byte(fields[1])
        self.d_drv, self.cs_drv = split_byte(fields[2])
        self.hd_drv, self.wp_drv = split_byte(fields[3])

        chip_id = fields[4]
        if chip_id != self.ROM_LOADER.IMAGE_CHIP_ID:
            print(("Unexpected chip id in image. Expected %d but value was %d. "
                   "Is this image for a different chip model?") % (self.ROM_LOADER.IMAGE_CHIP_ID, chip_id))

        self.min_rev = fields[5]
        self.min_rev_full = fields[6]
        self.max_rev_full = fields[7]

        # reserved fields in the middle should all be zero
        if any(f for f in fields[8:-1] if f != 0):
            print("Warning: some reserved header fields have non-zero values. This image may be from a newer esptool.py?")

        append_digest = fields[-1]  # last byte is append_digest
        if append_digest in [0, 1]:
            self.append_digest = (append_digest == 1)
        else:
            raise RuntimeError("Invalid value for append_digest field (0x%02x). Should be 0 or 1.", append_digest)

    def save_extended_header(self, save_file):
        def join_byte(ln, hn):
            return (ln & 0x0F) + ((hn & 0x0F) << 4)

        append_digest = 1 if self.append_digest else 0

        fields = [self.wp_pin,
                  join_byte(self.clk_drv, self.q_drv),
                  join_byte(self.d_drv, self.cs_drv),
                  join_byte(self.hd_drv, self.wp_drv),
                  self.ROM_LOADER.IMAGE_CHIP_ID,
                  self.min_rev,
                  self.min_rev_full,
                  self.max_rev_full]
        fields += [0] * 4  # padding
        fields += [append_digest]

        packed = struct.pack(self.EXTENDED_HEADER_STRUCT_FMT, *fields)
        save_file.write(packed)


class ESP8266V3FirmwareImage(ESP32FirmwareImage):
    """ ESP8266 V3 firmware image is very similar to ESP32 image
    """

    EXTENDED_HEADER_STRUCT_FMT = "B" * 16

    def is_flash_addr(self, addr):
        return (addr > ESP8266ROM.IROM_MAP_START)

    def save(self, filename):
        total_segments = 0
        with io.BytesIO() as f:  # write file to memory first
            self.write_common_header(f, self.segments)

            checksum = ESPLoader.ESP_CHECKSUM_MAGIC

            # split segments into flash-mapped vs ram-loaded, and take copies so we can mutate them
            flash_segments = [copy.deepcopy(s) for s in sorted(self.segments, key=lambda s:s.addr) if self.is_flash_addr(s.addr) and len(s.data)]
            ram_segments = [copy.deepcopy(s) for s in sorted(self.segments, key=lambda s:s.addr) if not self.is_flash_addr(s.addr) and len(s.data)]

            # check for multiple ELF sections that are mapped in the same flash mapping region.
            # this is usually a sign of a broken linker script, but if you have a legitimate
            # use case then let us know
            if len(flash_segments) > 0:
                last_addr = flash_segments[0].addr
                for segment in flash_segments[1:]:
                    if segment.addr // self.IROM_ALIGN == last_addr // self.IROM_ALIGN:
                        raise FatalError(("Segment loaded at 0x%08x lands in same 64KB flash mapping as segment loaded at 0x%08x. "
                                          "Can't generate binary. Suggest changing linker script or ELF to merge sections.") %
                                         (segment.addr, last_addr))
                    last_addr = segment.addr

            # try to fit each flash segment on a 64kB aligned boundary
            # by padding with parts of the non-flash segments...
            while len(flash_segments) > 0:
                segment = flash_segments[0]
                # remove 8 bytes empty data for insert segment header
                if segment.name == '.flash.rodata':
                    segment.data = segment.data[8:]
                # write the flash segment
                checksum = self.save_segment(f, segment, checksum)
                flash_segments.pop(0)
                total_segments += 1

            # flash segments all written, so write any remaining RAM segments
            for segment in ram_segments:
                checksum = self.save_segment(f, segment, checksum)
                total_segments += 1

            # done writing segments
            self.append_checksum(f, checksum)
            image_length = f.tell()

            # kinda hacky: go back to the initial header and write the new segment count
            # that includes padding segments. This header is not checksummed
            f.seek(1)
            try:
                f.write(chr(total_segments))
            except TypeError:  # Python 3
                f.write(bytes([total_segments]))

            if self.append_digest:
                # calculate the SHA256 of the whole file and append it
                f.seek(0)
                digest = hashlib.sha256()
                digest.update(f.read(image_length))
                f.write(digest.digest())

            with open(filename, 'wb') as real_file:
                real_file.write(f.getvalue())

    def load_extended_header(self, load_file):
        def split_byte(n):
            return (n & 0x0F, (n >> 4) & 0x0F)

        fields = list(struct.unpack(self.EXTENDED_HEADER_STRUCT_FMT, load_file.read(16)))

        self.wp_pin = fields[0]

        # SPI pin drive stengths are two per byte
        self.clk_drv, self.q_drv = split_byte(fields[1])
        self.d_drv, self.cs_drv = split_byte(fields[2])
        self.hd_drv, self.wp_drv = split_byte(fields[3])

        if fields[15] in [0, 1]:
            self.append_digest = (fields[15] == 1)
        else:
            raise RuntimeError("Invalid value for append_digest field (0x%02x). Should be 0 or 1.", fields[15])

        # remaining fields in the middle should all be zero
        if any(f for f in fields[4:15] if f != 0):
            print("Warning: some reserved header fields have non-zero values. This image may be from a newer esptool.py?")


ESP32ROM.BOOTLOADER_IMAGE = ESP32FirmwareImage


class ESP32S2FirmwareImage(ESP32FirmwareImage):
    """ ESP32S2 Firmware Image almost exactly the same as ESP32FirmwareImage """
    ROM_LOADER = ESP32S2ROM


ESP32S2ROM.BOOTLOADER_IMAGE = ESP32S2FirmwareImage


class ESP32S3FirmwareImage(ESP32FirmwareImage):
    """ ESP32S3 Firmware Image almost exactly the same as ESP32FirmwareImage """
    ROM_LOADER = ESP32S3ROM


ESP32S3ROM.BOOTLOADER_IMAGE = ESP32S3FirmwareImage


class ESP32C2FirmwareImage(ESP32FirmwareImage):
    """ESP32C2 Firmware Image almost exactly the same as ESP32FirmwareImage"""

    ROM_LOADER = ESP32C2ROM

    def set_mmu_page_size(self, size):
        if size not in [16384, 32768, 65536]:
            raise FatalError(
                "{} bytes is not a valid ESP32-C2 page size, "
                "select from 64KB, 32KB, 16KB.".format(size)
            )
        self.IROM_ALIGN = size


ESP32C2ROM.BOOTLOADER_IMAGE = ESP32C2FirmwareImage


class ESP32C3FirmwareImage(ESP32FirmwareImage):
    """ ESP32C3 Firmware Image almost exactly the same as ESP32FirmwareImage """
    ROM_LOADER = ESP32C3ROM


ESP32C3ROM.BOOTLOADER_IMAGE = ESP32C3FirmwareImage


class ESP32C5FirmwareImage(ESP32FirmwareImage):
    """ESP32C5 Firmware Image almost exactly the same as ESP32FirmwareImage"""

    ROM_LOADER = ESP32C5ROM

    def set_mmu_page_size(self, size):
        if size not in [8192, 16384, 32768, 65536]:
            raise FatalError(
                "{} bytes is not a valid ESP32-C5 page size, "
                "select from 64KB, 32KB, 16KB, 8KB.".format(size)
            )
        self.IROM_ALIGN = size


ESP32C5ROM.BOOTLOADER_IMAGE = ESP32C5FirmwareImage


class ESP32C6FirmwareImage(ESP32FirmwareImage):
    """ESP32C6 Firmware Image almost exactly the same as ESP32FirmwareImage"""

    ROM_LOADER = ESP32C6ROM

    def set_mmu_page_size(self, size):
        if size not in [8192, 16384, 32768, 65536]:
            raise FatalError(
                "{} bytes is not a valid ESP32-C6 page size, "
                "select from 64KB, 32KB, 16KB, 8KB.".format(size)
            )
        self.IROM_ALIGN = size


ESP32C6ROM.BOOTLOADER_IMAGE = ESP32C6FirmwareImage


class ESP32P4FirmwareImage(ESP32FirmwareImage):
    """ESP32P4 Firmware Image almost exactly the same as ESP32FirmwareImage"""

    ROM_LOADER = ESP32P4ROM

    def set_mmu_page_size(self, size):
        if size not in [8192, 16384, 32768, 65536]:
            raise FatalError(
                "{} bytes is not a valid ESP32-P4 page size, "
                "select from 64KB, 32KB, 16KB, 8KB.".format(size)
            )
        self.IROM_ALIGN = size


ESP32P4ROM.BOOTLOADER_IMAGE = ESP32P4FirmwareImage


class ESP32H2FirmwareImage(ESP32C6FirmwareImage):
    """ESP32H2 Firmware Image almost exactly the same as ESP32FirmwareImage"""

    ROM_LOADER = ESP32H2ROM


ESP32H2ROM.BOOTLOADER_IMAGE = ESP32H2FirmwareImage


class ESP32C2FirmwareImage(ESP32FirmwareImage):
    """ ESP32C2 Firmware Image almost exactly the same as ESP32FirmwareImage """
    ROM_LOADER = ESP32C2ROM

    def set_mmu_page_size(self, size):
        if size not in [16384, 32768, 65536]:
            raise FatalError("{} is not a valid page size.".format(size))
        self.IROM_ALIGN = size


ESP32C2ROM.BOOTLOADER_IMAGE = ESP32C2FirmwareImage


class ELFFile(object):
    SEC_TYPE_PROGBITS = 0x01
    SEC_TYPE_STRTAB = 0x03
    SEC_TYPE_INITARRAY = 0x0e
    SEC_TYPE_FINIARRAY = 0x0f

    PROG_SEC_TYPES = (SEC_TYPE_PROGBITS, SEC_TYPE_INITARRAY, SEC_TYPE_FINIARRAY)

    LEN_SEC_HEADER = 0x28

    SEG_TYPE_LOAD = 0x01
    LEN_SEG_HEADER = 0x20

    def __init__(self, name):
        # Load sections from the ELF file
        self.name = name
        with open(self.name, 'rb') as f:
            self._read_elf_file(f)

    def get_section(self, section_name):
        for s in self.sections:
            if s.name == section_name:
                return s
        raise ValueError("No section %s in ELF file" % section_name)

    def _read_elf_file(self, f):
        # read the ELF file header
        LEN_FILE_HEADER = 0x34
        try:
            (ident, _type, machine, _version,
             self.entrypoint, _phoff, shoff, _flags,
             _ehsize, _phentsize, _phnum, shentsize,
             shnum, shstrndx) = struct.unpack("<16sHHLLLLLHHHHHH", f.read(LEN_FILE_HEADER))
        except struct.error as e:
            raise FatalError("Failed to read a valid ELF header from %s: %s" % (self.name, e))

        if byte(ident, 0) != 0x7f or ident[1:4] != b'ELF':
            raise FatalError("%s has invalid ELF magic header" % self.name)
        if machine not in [0x5e, 0xf3]:
            raise FatalError("%s does not appear to be an Xtensa or an RISCV ELF file. e_machine=%04x" % (self.name, machine))
        if shentsize != self.LEN_SEC_HEADER:
            raise FatalError("%s has unexpected section header entry size 0x%x (not 0x%x)" % (self.name, shentsize, self.LEN_SEC_HEADER))
        if shnum == 0:
            raise FatalError("%s has 0 section headers" % (self.name))
        self._read_sections(f, shoff, shnum, shstrndx)
        self._read_segments(f, _phoff, _phnum, shstrndx)

    def _read_sections(self, f, section_header_offs, section_header_count, shstrndx):
        f.seek(section_header_offs)
        len_bytes = section_header_count * self.LEN_SEC_HEADER
        section_header = f.read(len_bytes)
        if len(section_header) == 0:
            raise FatalError("No section header found at offset %04x in ELF file." % section_header_offs)
        if len(section_header) != (len_bytes):
            raise FatalError("Only read 0x%x bytes from section header (expected 0x%x.) Truncated ELF file?" % (len(section_header), len_bytes))

        # walk through the section header and extract all sections
        section_header_offsets = range(0, len(section_header), self.LEN_SEC_HEADER)

        def read_section_header(offs):
            name_offs, sec_type, _flags, lma, sec_offs, size = struct.unpack_from("<LLLLLL", section_header[offs:])
            return (name_offs, sec_type, lma, size, sec_offs)
        all_sections = [read_section_header(offs) for offs in section_header_offsets]
        prog_sections = [s for s in all_sections if s[1] in ELFFile.PROG_SEC_TYPES]

        # search for the string table section
        if not (shstrndx * self.LEN_SEC_HEADER) in section_header_offsets:
            raise FatalError("ELF file has no STRTAB section at shstrndx %d" % shstrndx)
        _, sec_type, _, sec_size, sec_offs = read_section_header(shstrndx * self.LEN_SEC_HEADER)
        if sec_type != ELFFile.SEC_TYPE_STRTAB:
            print('WARNING: ELF file has incorrect STRTAB section type 0x%02x' % sec_type)
        f.seek(sec_offs)
        string_table = f.read(sec_size)

        # build the real list of ELFSections by reading the actual section names from the
        # string table section, and actual data for each section from the ELF file itself
        def lookup_string(offs):
            raw = string_table[offs:]
            return raw[:raw.index(b'\x00')]

        def read_data(offs, size):
            f.seek(offs)
            return f.read(size)

        prog_sections = [ELFSection(lookup_string(n_offs), lma, read_data(offs, size)) for (n_offs, _type, lma, size, offs) in prog_sections
                         if lma != 0 and size > 0]
        self.sections = prog_sections

    def _read_segments(self, f, segment_header_offs, segment_header_count, shstrndx):
        f.seek(segment_header_offs)
        len_bytes = segment_header_count * self.LEN_SEG_HEADER
        segment_header = f.read(len_bytes)
        if len(segment_header) == 0:
            raise FatalError("No segment header found at offset %04x in ELF file." % segment_header_offs)
        if len(segment_header) != (len_bytes):
            raise FatalError("Only read 0x%x bytes from segment header (expected 0x%x.) Truncated ELF file?" % (len(segment_header), len_bytes))

        # walk through the segment header and extract all segments
        segment_header_offsets = range(0, len(segment_header), self.LEN_SEG_HEADER)

        def read_segment_header(offs):
            seg_type, seg_offs, _vaddr, lma, size, _memsize, _flags, _align = struct.unpack_from("<LLLLLLLL", segment_header[offs:])
            return (seg_type, lma, size, seg_offs)
        all_segments = [read_segment_header(offs) for offs in segment_header_offsets]
        prog_segments = [s for s in all_segments if s[0] == ELFFile.SEG_TYPE_LOAD]

        def read_data(offs, size):
            f.seek(offs)
            return f.read(size)

        prog_segments = [ELFSection(b'PHDR', lma, read_data(offs, size)) for (_type, lma, size, offs) in prog_segments
                         if lma != 0 and size > 0]
        self.segments = prog_segments

    def sha256(self):
        # return SHA256 hash of the input ELF file
        sha256 = hashlib.sha256()
        with open(self.name, 'rb') as f:
            sha256.update(f.read())
        return sha256.digest()


def slip_reader(port, trace_function):
    """Generator to read SLIP packets from a serial port.
    Yields one full SLIP packet at a time, raises exception on timeout or invalid data.

    Designed to avoid too many calls to serial.read(1), which can bog
    down on slow systems.
    """
    partial_packet = None
    in_escape = False
    successful_slip = False
    while True:
        waiting = port.inWaiting()
        read_bytes = port.read(1 if waiting == 0 else waiting)
        if read_bytes == b'':
            if partial_packet is None:  # fail due to no data
                msg = "Serial data stream stopped: Possible serial noise or corruption." if successful_slip else "No serial data received."
            else:  # fail during packet transfer
                msg = "Packet content transfer stopped (received {} bytes)".format(len(partial_packet))
            trace_function(msg)
            raise FatalError(msg)
        trace_function("Read %d bytes: %s", len(read_bytes), HexFormatter(read_bytes))
        for b in read_bytes:
            if type(b) is int:
                b = bytes([b])  # python 2/3 compat

            if partial_packet is None:  # waiting for packet header
                if b == b'\xc0':
                    partial_packet = b""
                else:
                    trace_function("Read invalid data: %s", HexFormatter(read_bytes))
                    trace_function("Remaining data in serial buffer: %s", HexFormatter(port.read(port.inWaiting())))
                    raise FatalError('Invalid head of packet (0x%s): Possible serial noise or corruption.' % hexify(b))
            elif in_escape:  # part-way through escape sequence
                in_escape = False
                if b == b'\xdc':
                    partial_packet += b'\xc0'
                elif b == b'\xdd':
                    partial_packet += b'\xdb'
                else:
                    trace_function("Read invalid data: %s", HexFormatter(read_bytes))
                    trace_function("Remaining data in serial buffer: %s", HexFormatter(port.read(port.inWaiting())))
                    raise FatalError('Invalid SLIP escape (0xdb, 0x%s)' % (hexify(b)))
            elif b == b'\xdb':  # start of escape sequence
                in_escape = True
            elif b == b'\xc0':  # end of packet
                trace_function("Received full packet: %s", HexFormatter(partial_packet))
                yield partial_packet
                partial_packet = None
                successful_slip = True
            else:  # normal byte in packet
                partial_packet += b


def arg_auto_int(x):
    return int(x, 0)


def format_chip_name(c):
    """ Normalize chip name from user input """
    c = c.lower().replace('-', '')
    if c == 'esp8684':  # TODO: Delete alias, ESPTOOL-389
        print('WARNING: Chip name ESP8684 is deprecated in favor of ESP32-C2 and will be removed in a future release. Using ESP32-C2 instead.')
        return 'esp32c2'
    return c


def div_roundup(a, b):
    """ Return a/b rounded up to nearest integer,
    equivalent result to int(math.ceil(float(int(a)) / float(int(b))), only
    without possible floating point accuracy errors.
    """
    return (int(a) + int(b) - 1) // int(b)


def align_file_position(f, size):
    """ Align the position in the file to the next block of specified size """
    align = (size - 1) - (f.tell() % size)
    f.seek(align, 1)


def flash_size_bytes(size):
    """ Given a flash size of the type passed in args.flash_size
    (ie 512KB or 1MB) then return the size in bytes.
    """
    if "MB" in size:
        return int(size[:size.index("MB")]) * 1024 * 1024
    elif "KB" in size:
        return int(size[:size.index("KB")]) * 1024
    else:
        raise FatalError("Unknown size %s" % size)


def hexify(s, uppercase=True):
    format_str = '%02X' if uppercase else '%02x'
    if not PYTHON2:
        return ''.join(format_str % c for c in s)
    else:
        return ''.join(format_str % ord(c) for c in s)


class HexFormatter(object):
    """
    Wrapper class which takes binary data in its constructor
    and returns a hex string as it's __str__ method.

    This is intended for "lazy formatting" of trace() output
    in hex format. Avoids overhead (significant on slow computers)
    of generating long hex strings even if tracing is disabled.

    Note that this doesn't save any overhead if passed as an
    argument to "%", only when passed to trace()

    If auto_split is set (default), any long line (> 16 bytes) will be
    printed as separately indented lines, with ASCII decoding at the end
    of each line.
    """
    def __init__(self, binary_string, auto_split=True):
        self._s = binary_string
        self._auto_split = auto_split

    def __str__(self):
        if self._auto_split and len(self._s) > 16:
            result = ""
            s = self._s
            while len(s) > 0:
                line = s[:16]
                ascii_line = "".join(c if (c == ' ' or (c in string.printable and c not in string.whitespace))
                                     else '.' for c in line.decode('ascii', 'replace'))
                s = s[16:]
                result += "\n    %-16s %-16s | %s" % (hexify(line[:8], False), hexify(line[8:], False), ascii_line)
            return result
        else:
            return hexify(self._s, False)


def pad_to(data, alignment, pad_character=b'\xFF'):
    """ Pad to the next alignment boundary """
    pad_mod = len(data) % alignment
    if pad_mod != 0:
        data += pad_character * (alignment - pad_mod)
    return data


class FatalError(RuntimeError):
    """
    Wrapper class for runtime errors that aren't caused by internal bugs, but by
    ESP ROM responses or input content.
    """
    def __init__(self, message):
        RuntimeError.__init__(self, message)

    @staticmethod
    def WithResult(message, result):
        """
        Return a fatal error object that appends the hex values of
        'result' and its meaning as a string formatted argument.
        """

        err_defs = {
            0x101: 'Out of memory',
            0x102: 'Invalid argument',
            0x103: 'Invalid state',
            0x104: 'Invalid size',
            0x105: 'Requested resource not found',
            0x106: 'Operation or feature not supported',
            0x107: 'Operation timed out',
            0x108: 'Received response was invalid',
            0x109: 'CRC or checksum was invalid',
            0x10A: 'Version was invalid',
            0x10B: 'MAC address was invalid',
            # Flasher stub error codes
            0xC000: 'Bad data length',
            0xC100: 'Bad data checksum',
            0xC200: 'Bad blocksize',
            0xC300: 'Invalid command',
            0xC400: 'Failed SPI operation',
            0xC500: 'Failed SPI unlock',
            0xC600: 'Not in flash mode',
            0xC700: 'Inflate error',
            0xC800: 'Not enough data',
            0xC900: 'Too much data',
            0xFF00: 'Command not implemented',
        }

        err_code = struct.unpack(">H", result[:2])
        message += " (result was {}: {})".format(hexify(result), err_defs.get(err_code[0], 'Unknown result'))
        return FatalError(message)


class NotImplementedInROMError(FatalError):
    """
    Wrapper class for the error thrown when a particular ESP bootloader function
    is not implemented in the ROM bootloader.
    """
    def __init__(self, bootloader, func):
        FatalError.__init__(self, "%s ROM does not support function %s." % (bootloader.CHIP_NAME, func.__name__))


class NotSupportedError(FatalError):
    def __init__(self, esp, function_name):
        FatalError.__init__(self, "Function %s is not supported for %s." % (function_name, esp.CHIP_NAME))

# "Operation" commands, executable at command line. One function each
#
# Each function takes either two args (<ESPLoader instance>, <args>) or a single <args>
# argument.


class UnsupportedCommandError(RuntimeError):
    """
    Wrapper class for when ROM loader returns an invalid command response.

    Usually this indicates the loader is running in Secure Download Mode.
    """
    def __init__(self, esp, op):
        if esp.secure_download_mode:
            msg = "This command (0x%x) is not supported in Secure Download Mode" % op
        else:
            msg = "Invalid (unsupported) command 0x%x" % op
        RuntimeError.__init__(self, msg)


def load_ram(esp, args):
    image = LoadFirmwareImage(esp.CHIP_NAME, args.filename)

    print('RAM boot...')
    for seg in image.segments:
        size = len(seg.data)
        print('Downloading %d bytes at %08x...' % (size, seg.addr), end=' ')
        sys.stdout.flush()
        esp.mem_begin(size, div_roundup(size, esp.ESP_RAM_BLOCK), esp.ESP_RAM_BLOCK, seg.addr)

        seq = 0
        while len(seg.data) > 0:
            esp.mem_block(seg.data[0:esp.ESP_RAM_BLOCK], seq)
            seg.data = seg.data[esp.ESP_RAM_BLOCK:]
            seq += 1
        print('done!')

    print('All segments done, executing at %08x' % image.entrypoint)
    esp.mem_finish(image.entrypoint)


def read_mem(esp, args):
    print('0x%08x = 0x%08x' % (args.address, esp.read_reg(args.address)))


def write_mem(esp, args):
    esp.write_reg(args.address, args.value, args.mask, 0)
    print('Wrote %08x, mask %08x to %08x' % (args.value, args.mask, args.address))


def dump_mem(esp, args):
    with open(args.filename, 'wb') as f:
        for i in range(args.size // 4):
            d = esp.read_reg(args.address + (i * 4))
            f.write(struct.pack(b'<I', d))
            if f.tell() % 1024 == 0:
                print_overwrite('%d bytes read... (%d %%)' % (f.tell(),
                                                              f.tell() * 100 // args.size))
            sys.stdout.flush()
        print_overwrite("Read %d bytes" % f.tell(), last_line=True)
    print('Done!')


def detect_flash_size(esp, args):
    if args.flash_size == 'detect':
        if esp.secure_download_mode:
            raise FatalError("Detecting flash size is not supported in secure download mode. Need to manually specify flash size.")
        flash_id = esp.flash_id()
        size_id = flash_id >> 16
        args.flash_size = DETECTED_FLASH_SIZES.get(size_id)
        if args.flash_size is None:
            print('Warning: Could not auto-detect Flash size (FlashID=0x%x, SizeID=0x%x), defaulting to 4MB' % (flash_id, size_id))
            args.flash_size = '4MB'
        else:
            print('Auto-detected Flash size:', args.flash_size)


def _update_image_flash_params(esp, address, args, image):
    """ Modify the flash mode & size bytes if this looks like an executable bootloader image  """
    if len(image) < 8:
        return image  # not long enough to be a bootloader image

    # unpack the (potential) image header
    magic, _, flash_mode, flash_size_freq = struct.unpack("BBBB", image[:4])
    if address != esp.BOOTLOADER_FLASH_OFFSET:
        return image  # not flashing bootloader offset, so don't modify this

    if (args.flash_mode, args.flash_freq, args.flash_size) == ('keep',) * 3:
        return image  # all settings are 'keep', not modifying anything

    # easy check if this is an image: does it start with a magic byte?
    if magic != esp.ESP_IMAGE_MAGIC:
        print("Warning: Image file at 0x%x doesn't look like an image file, so not changing any flash settings." % address)
        return image

    # make sure this really is an image, and not just data that
    # starts with esp.ESP_IMAGE_MAGIC (mostly a problem for encrypted
    # images that happen to start with a magic byte
    try:
        test_image = esp.BOOTLOADER_IMAGE(io.BytesIO(image))
        test_image.verify()
    except Exception:
        print("Warning: Image file at 0x%x is not a valid %s image, so not changing any flash settings." % (address, esp.CHIP_NAME))
        return image

    if args.flash_mode != 'keep':
        flash_mode = {'qio': 0, 'qout': 1, 'dio': 2, 'dout': 3}[args.flash_mode]

    flash_freq = flash_size_freq & 0x0F
    if args.flash_freq != 'keep':
        flash_freq = esp.parse_flash_freq_arg(args.flash_freq)

    flash_size = flash_size_freq & 0xF0
    if args.flash_size != 'keep':
        flash_size = esp.parse_flash_size_arg(args.flash_size)

    flash_params = struct.pack(b'BB', flash_mode, flash_size + flash_freq)
    if flash_params != image[2:4]:
        print('Flash params set to 0x%04x' % struct.unpack(">H", flash_params))
        image = image[0:2] + flash_params + image[4:]
    return image


def write_flash(esp, args):
    # set args.compress based on default behaviour:
    # -> if either --compress or --no-compress is set, honour that
    # -> otherwise, set --compress unless --no-stub is set
    if args.compress is None and not args.no_compress:
        args.compress = not args.no_stub

    # In case we have encrypted files to write, we first do few sanity checks before actual flash
    if args.encrypt or args.encrypt_files is not None:
        do_write = True

        if not esp.secure_download_mode:
            if esp.get_encrypted_download_disabled():
                raise FatalError("This chip has encrypt functionality in UART download mode disabled. "
                                 "This is the Flash Encryption configuration for Production mode instead of Development mode.")

            crypt_cfg_efuse = esp.get_flash_crypt_config()

            if crypt_cfg_efuse is not None and crypt_cfg_efuse != 0xF:
                print('Unexpected FLASH_CRYPT_CONFIG value: 0x%x' % (crypt_cfg_efuse))
                do_write = False

            enc_key_valid = esp.is_flash_encryption_key_valid()

            if not enc_key_valid:
                print('Flash encryption key is not programmed')
                do_write = False

        # Determine which files list contain the ones to encrypt
        files_to_encrypt = args.addr_filename if args.encrypt else args.encrypt_files

        for address, argfile in files_to_encrypt:
            if address % esp.FLASH_ENCRYPTED_WRITE_ALIGN:
                print("File %s address 0x%x is not %d byte aligned, can't flash encrypted" %
                      (argfile.name, address, esp.FLASH_ENCRYPTED_WRITE_ALIGN))
                do_write = False

        if not do_write and not args.ignore_flash_encryption_efuse_setting:
            raise FatalError("Can't perform encrypted flash write, consult Flash Encryption documentation for more information")

    # verify file sizes fit in flash
    if args.flash_size != 'keep':  # TODO: check this even with 'keep'
        flash_end = flash_size_bytes(args.flash_size)
        for address, argfile in args.addr_filename:
            argfile.seek(0, os.SEEK_END)
            if address + argfile.tell() > flash_end:
                raise FatalError(("File %s (length %d) at offset %d will not fit in %d bytes of flash. "
                                  "Use --flash_size argument, or change flashing address.")
                                 % (argfile.name, argfile.tell(), address, flash_end))
            argfile.seek(0)

    if args.erase_all:
        erase_flash(esp, args)
    else:
        for address, argfile in args.addr_filename:
            argfile.seek(0, os.SEEK_END)
            write_end = address + argfile.tell()
            argfile.seek(0)
            bytes_over = address % esp.FLASH_SECTOR_SIZE
            if bytes_over != 0:
                print("WARNING: Flash address {:#010x} is not aligned to a {:#x} byte flash sector. "
                      "{:#x} bytes before this address will be erased."
                      .format(address, esp.FLASH_SECTOR_SIZE, bytes_over))
            # Print the address range of to-be-erased flash memory region
            print("Flash will be erased from {:#010x} to {:#010x}..."
                  .format(address - bytes_over, div_roundup(write_end, esp.FLASH_SECTOR_SIZE) * esp.FLASH_SECTOR_SIZE - 1))

    """ Create a list describing all the files we have to flash. Each entry holds an "encrypt" flag
    marking whether the file needs encryption or not. This list needs to be sorted.

    First, append to each entry of our addr_filename list the flag args.encrypt
    For example, if addr_filename is [(0x1000, "partition.bin"), (0x8000, "bootloader")],
    all_files will be [(0x1000, "partition.bin", args.encrypt), (0x8000, "bootloader", args.encrypt)],
    where, of course, args.encrypt is either True or False
    """
    all_files = [(offs, filename, args.encrypt) for (offs, filename) in args.addr_filename]

    """Now do the same with encrypt_files list, if defined.
    In this case, the flag is True
    """
    if args.encrypt_files is not None:
        encrypted_files_flag = [(offs, filename, True) for (offs, filename) in args.encrypt_files]

        # Concatenate both lists and sort them.
        # As both list are already sorted, we could simply do a merge instead,
        # but for the sake of simplicity and because the lists are very small,
        # let's use sorted.
        all_files = sorted(all_files + encrypted_files_flag, key=lambda x: x[0])

    for address, argfile, encrypted in all_files:
        compress = args.compress

        # Check whether we can compress the current file before flashing
        if compress and encrypted:
            print('\nWARNING: - compress and encrypt options are mutually exclusive ')
            print('Will flash %s uncompressed' % argfile.name)
            compress = False

        if args.no_stub:
            print('Erasing flash...')
        image = pad_to(argfile.read(), esp.FLASH_ENCRYPTED_WRITE_ALIGN if encrypted else 4)
        if len(image) == 0:
            print('WARNING: File %s is empty' % argfile.name)
            continue
        image = _update_image_flash_params(esp, address, args, image)
        calcmd5 = hashlib.md5(image).hexdigest()
        uncsize = len(image)
        if compress:
            uncimage = image
            image = zlib.compress(uncimage, 9)
            # Decompress the compressed binary a block at a time, to dynamically calculate the
            # timeout based on the real write size
            decompress = zlib.decompressobj()
            blocks = esp.flash_defl_begin(uncsize, len(image), address)
        else:
            blocks = esp.flash_begin(uncsize, address, begin_rom_encrypted=encrypted)
        argfile.seek(0)  # in case we need it again
        seq = 0
        bytes_sent = 0  # bytes sent on wire
        bytes_written = 0  # bytes written to flash
        t = time.time()

        timeout = DEFAULT_TIMEOUT

        while len(image) > 0:
            print_overwrite('Writing at 0x%08x... (%d %%)' % (address + bytes_written, 100 * (seq + 1) // blocks))
            sys.stdout.flush()
            block = image[0:esp.FLASH_WRITE_SIZE]
            if compress:
                # feeding each compressed block into the decompressor lets us see block-by-block how much will be written
                block_uncompressed = len(decompress.decompress(block))
                bytes_written += block_uncompressed
                block_timeout = max(DEFAULT_TIMEOUT, timeout_per_mb(ERASE_WRITE_TIMEOUT_PER_MB, block_uncompressed))
                if not esp.IS_STUB:
                    timeout = block_timeout  # ROM code writes block to flash before ACKing
                esp.flash_defl_block(block, seq, timeout=timeout)
                if esp.IS_STUB:
                    timeout = block_timeout  # Stub ACKs when block is received, then writes to flash while receiving the block after it
            else:
                # Pad the last block
                block = block + b'\xff' * (esp.FLASH_WRITE_SIZE - len(block))
                if encrypted:
                    esp.flash_encrypt_block(block, seq)
                else:
                    esp.flash_block(block, seq)
                bytes_written += len(block)
            bytes_sent += len(block)
            image = image[esp.FLASH_WRITE_SIZE:]
            seq += 1

        if esp.IS_STUB:
            # Stub only writes each block to flash after 'ack'ing the receive, so do a final dummy operation which will
            # not be 'ack'ed until the last block has actually been written out to flash
            esp.read_reg(ESPLoader.CHIP_DETECT_MAGIC_REG_ADDR, timeout=timeout)

        t = time.time() - t
        speed_msg = ""
        if compress:
            if t > 0.0:
                speed_msg = " (effective %.1f kbit/s)" % (uncsize / t * 8 / 1000)
            print_overwrite('Wrote %d bytes (%d compressed) at 0x%08x in %.1f seconds%s...' % (uncsize,
                                                                                               bytes_sent,
                                                                                               address, t, speed_msg), last_line=True)
        else:
            if t > 0.0:
                speed_msg = " (%.1f kbit/s)" % (bytes_written / t * 8 / 1000)
            print_overwrite('Wrote %d bytes at 0x%08x in %.1f seconds%s...' % (bytes_written, address, t, speed_msg), last_line=True)

        if not encrypted and not esp.secure_download_mode:
            try:
                res = esp.flash_md5sum(address, uncsize)
                if res != calcmd5:
                    print('File  md5: %s' % calcmd5)
                    print('Flash md5: %s' % res)
                    print('MD5 of 0xFF is %s' % (hashlib.md5(b'\xFF' * uncsize).hexdigest()))
                    raise FatalError("MD5 of file does not match data in flash!")
                else:
                    print('Hash of data verified.')
            except NotImplementedInROMError:
                pass

    print('\nLeaving...')

    if esp.IS_STUB:
        # skip sending flash_finish to ROM loader here,
        # as it causes the loader to exit and run user code
        esp.flash_begin(0, 0)

        # Get the "encrypted" flag for the last file flashed
        # Note: all_files list contains triplets like:
        # (address: Integer, filename: String, encrypted: Boolean)
        last_file_encrypted = all_files[-1][2]

        # Check whether the last file flashed was compressed or not
        if args.compress and not last_file_encrypted:
            esp.flash_defl_finish(False)
        else:
            esp.flash_finish(False)

    if args.verify:
        print('Verifying just-written flash...')
        print('(This option is deprecated, flash contents are now always read back after flashing.)')
        # If some encrypted files have been flashed print a warning saying that we won't check them
        if args.encrypt or args.encrypt_files is not None:
            print('WARNING: - cannot verify encrypted files, they will be ignored')
        # Call verify_flash function only if there at least one non-encrypted file flashed
        if not args.encrypt:
            verify_flash(esp, args)


def image_info(args):
    if args.chip == "auto":
        print("WARNING: --chip not specified, defaulting to ESP8266.")
    image = LoadFirmwareImage(args.chip, args.filename)
    print('Image version: %d' % image.version)
    if args.chip != 'auto' and args.chip != 'esp8266':
        print(
            "Minimal chip revision:",
            "v{}.{},".format(image.min_rev_full // 100, image.min_rev_full % 100),
            "(legacy min_rev = {})".format(image.min_rev)
        )
        print(
            "Maximal chip revision:",
            "v{}.{}".format(image.max_rev_full // 100, image.max_rev_full % 100),
        )
    print('Entry point: %08x' % image.entrypoint if image.entrypoint != 0 else 'Entry point not set')
    print('%d segments' % len(image.segments))
    print()
    idx = 0
    for seg in image.segments:
        idx += 1
        segs = seg.get_memory_type(image)
        seg_name = ",".join(segs)
        print('Segment %d: %r [%s]' % (idx, seg, seg_name))
    calc_checksum = image.calculate_checksum()
    print('Checksum: %02x (%s)' % (image.checksum,
                                   'valid' if image.checksum == calc_checksum else 'invalid - calculated %02x' % calc_checksum))
    try:
        digest_msg = 'Not appended'
        if image.append_digest:
            is_valid = image.stored_digest == image.calc_digest
            digest_msg = "%s (%s)" % (hexify(image.calc_digest).lower(),
                                      "valid" if is_valid else "invalid")
            print('Validation Hash: %s' % digest_msg)
    except AttributeError:
        pass  # ESP8266 image has no append_digest field


def make_image(args):
    image = ESP8266ROMFirmwareImage()
    if len(args.segfile) == 0:
        raise FatalError('No segments specified')
    if len(args.segfile) != len(args.segaddr):
        raise FatalError('Number of specified files does not match number of specified addresses')
    for (seg, addr) in zip(args.segfile, args.segaddr):
        with open(seg, 'rb') as f:
            data = f.read()
            image.segments.append(ImageSegment(addr, data))
    image.entrypoint = args.entrypoint
    image.save(args.output)


def elf2image(args):
    e = ELFFile(args.input)
    if args.chip == 'auto':  # Default to ESP8266 for backwards compatibility
        args.chip = 'esp8266'

    print("Creating {} image...".format(args.chip))

    if args.chip == 'esp32':
        image = ESP32FirmwareImage()
        if args.secure_pad:
            image.secure_pad = '1'
        elif args.secure_pad_v2:
            image.secure_pad = '2'
    elif args.chip == 'esp32s2':
        image = ESP32S2FirmwareImage()
        if args.secure_pad_v2:
            image.secure_pad = '2'
    elif args.chip == 'esp32s3':
        image = ESP32S3FirmwareImage()
        if args.secure_pad_v2:
            image.secure_pad = '2'
    elif args.chip == 'esp32c3':
        image = ESP32C3FirmwareImage()
        if args.secure_pad_v2:
            image.secure_pad = '2'
    elif args.chip == 'esp32c5':
        image = ESP32C5FirmwareImage()
        if args.secure_pad_v2:
            image.secure_pad = '2'
    elif args.chip == 'esp32c6':
        image = ESP32C6FirmwareImage()
        if args.secure_pad_v2:
            image.secure_pad = '2'
    elif args.chip == 'esp32h2':
        image = ESP32H2FirmwareImage()
        if args.secure_pad_v2:
            image.secure_pad = '2'
    elif args.chip == 'esp32c2':
        image = ESP32C2FirmwareImage()
        if args.secure_pad_v2:
            image.secure_pad = '2'
    elif args.chip == 'esp32p4':
        image = ESP32P4FirmwareImage()
        if args.secure_pad_v2:
            image.secure_pad = '2'
    elif args.version == '1':  # ESP8266
        image = ESP8266ROMFirmwareImage()
    elif args.version == '2':
        image = ESP8266V2FirmwareImage()
    else:
        image = ESP8266V3FirmwareImage()
    image.entrypoint = e.entrypoint
    image.flash_mode = {'qio': 0, 'qout': 1, 'dio': 2, 'dout': 3}[args.flash_mode]

    if args.chip != 'esp8266':
        image.min_rev = args.min_rev
        image.min_rev_full = args.min_rev_full
        image.max_rev_full = args.max_rev_full

    if args.flash_mmu_page_size:
        image.set_mmu_page_size(flash_size_bytes(args.flash_mmu_page_size))

    # ELFSection is a subclass of ImageSegment, so can use interchangeably
    image.segments = e.segments if args.use_segments else e.sections

    if args.pad_to_size:
        image.pad_to_size = flash_size_bytes(args.pad_to_size)

    image.flash_size_freq = image.ROM_LOADER.parse_flash_size_arg(args.flash_size)
    image.flash_size_freq += image.ROM_LOADER.parse_flash_freq_arg(args.flash_freq)

    if args.elf_sha256_offset:
        image.elf_sha256 = e.sha256()
        image.elf_sha256_offset = args.elf_sha256_offset

    before = len(image.segments)
    image.merge_adjacent_segments()
    if len(image.segments) != before:
        delta = before - len(image.segments)
        print("Merged %d ELF section%s" % (delta, "s" if delta > 1 else ""))

    image.verify()

    if args.output is None:
        args.output = image.default_output_name(args.input)
    image.save(args.output)

    print("Successfully created {} image.".format(args.chip))


def read_mac(esp, args):
    mac = esp.read_mac()

    def print_mac(label, mac):
        print('%s: %s' % (label, ':'.join(map(lambda x: '%02x' % x, mac))))
    print_mac("MAC", mac)


def chip_id(esp, args):
    try:
        chipid = esp.chip_id()
        print('Chip ID: 0x%08x' % chipid)
    except NotSupportedError:
        print('Warning: %s has no Chip ID. Reading MAC instead.' % esp.CHIP_NAME)
        read_mac(esp, args)


def erase_flash(esp, args):
    print('Erasing flash (this may take a while)...')
    t = time.time()
    esp.erase_flash()
    print('Chip erase completed successfully in %.1fs' % (time.time() - t))


def erase_region(esp, args):
    print('Erasing region (may be slow depending on size)...')
    t = time.time()
    esp.erase_region(args.address, args.size)
    print('Erase completed successfully in %.1f seconds.' % (time.time() - t))


def run(esp, args):
    esp.run()


def flash_id(esp, args):
    flash_id = esp.flash_id()
    print('Manufacturer: %02x' % (flash_id & 0xff))
    flid_lowbyte = (flash_id >> 16) & 0xFF
    print('Device: %02x%02x' % ((flash_id >> 8) & 0xff, flid_lowbyte))
    print('Detected flash size: %s' % (DETECTED_FLASH_SIZES.get(flid_lowbyte, "Unknown")))


def read_flash(esp, args):
    if args.no_progress:
        flash_progress = None
    else:
        def flash_progress(progress, length):
            msg = '%d (%d %%)' % (progress, progress * 100.0 / length)
            padding = '\b' * len(msg)
            if progress == length:
                padding = '\n'
            sys.stdout.write(msg + padding)
            sys.stdout.flush()
    t = time.time()
    data = esp.read_flash(args.address, args.size, flash_progress)
    t = time.time() - t
    print_overwrite('Read %d bytes at 0x%x in %.1f seconds (%.1f kbit/s)...'
                    % (len(data), args.address, t, len(data) / t * 8 / 1000), last_line=True)
    with open(args.filename, 'wb') as f:
        f.write(data)


def verify_flash(esp, args):
    differences = False

    for address, argfile in args.addr_filename:
        image = pad_to(argfile.read(), 4)
        argfile.seek(0)  # rewind in case we need it again

        image = _update_image_flash_params(esp, address, args, image)

        image_size = len(image)
        print('Verifying 0x%x (%d) bytes @ 0x%08x in flash against %s...' % (image_size, image_size, address, argfile.name))
        # Try digest first, only read if there are differences.
        digest = esp.flash_md5sum(address, image_size)
        expected_digest = hashlib.md5(image).hexdigest()
        if digest == expected_digest:
            print('-- verify OK (digest matched)')
            continue
        else:
            differences = True
            if getattr(args, 'diff', 'no') != 'yes':
                print('-- verify FAILED (digest mismatch)')
                continue

        flash = esp.read_flash(address, image_size)
        assert flash != image
        diff = [i for i in range(image_size) if flash[i] != image[i]]
        print('-- verify FAILED: %d differences, first @ 0x%08x' % (len(diff), address + diff[0]))
        for d in diff:
            flash_byte = flash[d]
            image_byte = image[d]
            if PYTHON2:
                flash_byte = ord(flash_byte)
                image_byte = ord(image_byte)
            print('   %08x %02x %02x' % (address + d, flash_byte, image_byte))
    if differences:
        raise FatalError("Verify failed.")


def read_flash_status(esp, args):
    print('Status value: 0x%04x' % esp.read_status(args.bytes))


def write_flash_status(esp, args):
    fmt = "0x%%0%dx" % (args.bytes * 2)
    args.value = args.value & ((1 << (args.bytes * 8)) - 1)
    print(('Initial flash status: ' + fmt) % esp.read_status(args.bytes))
    print(('Setting flash status: ' + fmt) % args.value)
    esp.write_status(args.value, args.bytes, args.non_volatile)
    print(('After flash status:   ' + fmt) % esp.read_status(args.bytes))


def get_security_info(esp, args):
    si = esp.get_security_info()
    # TODO: better display and tests
    print('Flags: {:#010x} ({})'.format(si["flags"], bin(si["flags"])))
    print('Flash_Crypt_Cnt: {:#x}'.format(si["flash_crypt_cnt"]))
    print('Key_Purposes: {}'.format(si["key_purposes"]))
    if si["chip_id"] is not None and si["api_version"] is not None:
        print('Chip_ID: {}'.format(si["chip_id"]))
        print('Api_Version: {}'.format(si["api_version"]))


def merge_bin(args):
    try:
        chip_class = _chip_to_rom_loader(args.chip)
    except KeyError:
        msg = "Please specify the chip argument" if args.chip == "auto" else "Invalid chip choice: '{}'".format(args.chip)
        msg = msg + " (choose from {})".format(', '.join(SUPPORTED_CHIPS))
        raise FatalError(msg)

    # sort the files by offset. The AddrFilenamePairAction has already checked for overlap
    input_files = sorted(args.addr_filename, key=lambda x: x[0])
    if not input_files:
        raise FatalError("No input files specified")
    first_addr = input_files[0][0]
    if first_addr < args.target_offset:
        raise FatalError("Output file target offset is 0x%x. Input file offset 0x%x is before this." % (args.target_offset, first_addr))

    if args.format != 'raw':
        raise FatalError("This version of esptool only supports the 'raw' output format")

    with open(args.output, 'wb') as of:
        def pad_to(flash_offs):
            # account for output file offset if there is any
            of.write(b'\xFF' * (flash_offs - args.target_offset - of.tell()))
        for addr, argfile in input_files:
            pad_to(addr)
            image = argfile.read()
            image = _update_image_flash_params(chip_class, addr, args, image)
            of.write(image)
        if args.fill_flash_size:
            pad_to(flash_size_bytes(args.fill_flash_size))
        print("Wrote 0x%x bytes to file %s, ready to flash to offset 0x%x" % (of.tell(), args.output, args.target_offset))


def version(args):
    print(__version__)

#
# End of operations functions
#


def main(argv=None, esp=None):
    """
    Main function for esptool

    argv - Optional override for default arguments parsing (that uses sys.argv), can be a list of custom arguments
    as strings. Arguments and their values need to be added as individual items to the list e.g. "-b 115200" thus
    becomes ['-b', '115200'].

    esp - Optional override of the connected device previously returned by get_default_connected_device()
    """

    external_esp = esp is not None

    parser = argparse.ArgumentParser(description='esptool.py v%s - Espressif chips ROM Bootloader Utility' % __version__, prog='esptool')

    parser.add_argument('--chip', '-c',
                        help='Target chip type',
                        type=format_chip_name,  # support ESP32-S2, etc.
                        choices=['auto'] + SUPPORTED_CHIPS,
                        default=os.environ.get('ESPTOOL_CHIP', 'auto'))

    parser.add_argument(
        '--port', '-p',
        help='Serial port device',
        default=os.environ.get('ESPTOOL_PORT', None))

    parser.add_argument(
        '--baud', '-b',
        help='Serial port baud rate used when flashing/reading',
        type=arg_auto_int,
        default=os.environ.get('ESPTOOL_BAUD', ESPLoader.ESP_ROM_BAUD))

    parser.add_argument(
        '--before',
        help='What to do before connecting to the chip',
        choices=['default_reset', 'usb_reset', 'no_reset', 'no_reset_no_sync'],
        default=os.environ.get('ESPTOOL_BEFORE', 'default_reset'))

    parser.add_argument(
        '--after', '-a',
        help='What to do after esptool.py is finished',
        choices=['hard_reset', 'soft_reset', 'no_reset', 'no_reset_stub'],
        default=os.environ.get('ESPTOOL_AFTER', 'hard_reset'))

    parser.add_argument(
        '--no-stub',
        help="Disable launching the flasher stub, only talk to ROM bootloader. Some features will not be available.",
        action='store_true')

    parser.add_argument(
        '--trace', '-t',
        help="Enable trace-level output of esptool.py interactions.",
        action='store_true')

    parser.add_argument(
        '--override-vddsdio',
        help="Override ESP32 VDDSDIO internal voltage regulator (use with care)",
        choices=ESP32ROM.OVERRIDE_VDDSDIO_CHOICES,
        nargs='?')

    parser.add_argument(
        '--connect-attempts',
        help=('Number of attempts to connect, negative or 0 for infinite. '
              'Default: %d.' % DEFAULT_CONNECT_ATTEMPTS),
        type=int,
        default=os.environ.get('ESPTOOL_CONNECT_ATTEMPTS', DEFAULT_CONNECT_ATTEMPTS))

    subparsers = parser.add_subparsers(
        dest='operation',
        help='Run esptool {command} -h for additional help')

    def add_spi_connection_arg(parent):
        parent.add_argument('--spi-connection', '-sc', help='ESP32-only argument. Override default SPI Flash connection. '
                            'Value can be SPI, HSPI or a comma-separated list of 5 I/O numbers to use for SPI flash (CLK,Q,D,HD,CS).',
                            action=SpiConnectionAction)

    parser_load_ram = subparsers.add_parser(
        'load_ram',
        help='Download an image to RAM and execute')
    parser_load_ram.add_argument('filename', help='Firmware image')

    parser_dump_mem = subparsers.add_parser(
        'dump_mem',
        help='Dump arbitrary memory to disk')
    parser_dump_mem.add_argument('address', help='Base address', type=arg_auto_int)
    parser_dump_mem.add_argument('size', help='Size of region to dump', type=arg_auto_int)
    parser_dump_mem.add_argument('filename', help='Name of binary dump')

    parser_read_mem = subparsers.add_parser(
        'read_mem',
        help='Read arbitrary memory location')
    parser_read_mem.add_argument('address', help='Address to read', type=arg_auto_int)

    parser_write_mem = subparsers.add_parser(
        'write_mem',
        help='Read-modify-write to arbitrary memory location')
    parser_write_mem.add_argument('address', help='Address to write', type=arg_auto_int)
    parser_write_mem.add_argument('value', help='Value', type=arg_auto_int)
    parser_write_mem.add_argument('mask', help='Mask of bits to write', type=arg_auto_int, nargs='?', default='0xFFFFFFFF')

    def add_spi_flash_subparsers(parent, allow_keep, auto_detect):
        """ Add common parser arguments for SPI flash properties """
        extra_keep_args = ['keep'] if allow_keep else []

        if auto_detect and allow_keep:
            extra_fs_message = ", detect, or keep"
        elif auto_detect:
            extra_fs_message = ", or detect"
        elif allow_keep:
            extra_fs_message = ", or keep"
        else:
            extra_fs_message = ""

        parent.add_argument('--flash_freq', '-ff', help='SPI Flash frequency',
                            choices=extra_keep_args + ['80m', '60m', '48m', '40m', '30m', '26m', '24m', '20m', '16m', '15m', '12m'],
                            default=os.environ.get('ESPTOOL_FF', 'keep' if allow_keep else '40m'))
        parent.add_argument('--flash_mode', '-fm', help='SPI Flash mode',
                            choices=extra_keep_args + ['qio', 'qout', 'dio', 'dout'],
                            default=os.environ.get('ESPTOOL_FM', 'keep' if allow_keep else 'qio'))
        parent.add_argument('--flash_size', '-fs', help='SPI Flash size in MegaBytes (1MB, 2MB, 4MB, 8MB, 16MB, 32MB, 64MB, 128MB)'
                            ' plus ESP8266-only (256KB, 512KB, 2MB-c1, 4MB-c1)' + extra_fs_message,
                            action=FlashSizeAction, auto_detect=auto_detect,
                            default=os.environ.get('ESPTOOL_FS', 'keep' if allow_keep else '1MB'))
        add_spi_connection_arg(parent)

    parser_write_flash = subparsers.add_parser(
        'write_flash',
        help='Write a binary blob to flash')

    parser_write_flash.add_argument('addr_filename', metavar='<address> <filename>', help='Address followed by binary filename, separated by space',
                                    action=AddrFilenamePairAction)
    parser_write_flash.add_argument('--erase-all', '-e',
                                    help='Erase all regions of flash (not just write areas) before programming',
                                    action="store_true")

    add_spi_flash_subparsers(parser_write_flash, allow_keep=True, auto_detect=True)
    parser_write_flash.add_argument('--no-progress', '-p', help='Suppress progress output', action="store_true")
    parser_write_flash.add_argument('--verify', help='Verify just-written data on flash '
                                    '(mostly superfluous, data is read back during flashing)', action='store_true')
    parser_write_flash.add_argument('--encrypt', help='Apply flash encryption when writing data (required correct efuse settings)',
                                    action='store_true')
    # In order to not break backward compatibility, our list of encrypted files to flash is a new parameter
    parser_write_flash.add_argument('--encrypt-files', metavar='<address> <filename>',
                                    help='Files to be encrypted on the flash. Address followed by binary filename, separated by space.',
                                    action=AddrFilenamePairAction)
    parser_write_flash.add_argument('--ignore-flash-encryption-efuse-setting', help='Ignore flash encryption efuse settings ',
                                    action='store_true')

    compress_args = parser_write_flash.add_mutually_exclusive_group(required=False)
    compress_args.add_argument('--compress', '-z', help='Compress data in transfer (default unless --no-stub is specified)',
                               action="store_true", default=None)
    compress_args.add_argument('--no-compress', '-u', help='Disable data compression during transfer (default if --no-stub is specified)',
                               action="store_true")

    subparsers.add_parser(
        'run',
        help='Run application code in flash')

    parser_image_info = subparsers.add_parser(
        'image_info',
        help='Dump headers from an application image')
    parser_image_info.add_argument('filename', help='Image file to parse')

    parser_make_image = subparsers.add_parser(
        'make_image',
        help='Create an application image from binary files')
    parser_make_image.add_argument('output', help='Output image file')
    parser_make_image.add_argument('--segfile', '-f', action='append', help='Segment input file')
    parser_make_image.add_argument('--segaddr', '-a', action='append', help='Segment base address', type=arg_auto_int)
    parser_make_image.add_argument('--entrypoint', '-e', help='Address of entry point', type=arg_auto_int, default=0)

    parser_elf2image = subparsers.add_parser(
        'elf2image',
        help='Create an application image from ELF file')
    parser_elf2image.add_argument('input', help='Input ELF file')
    parser_elf2image.add_argument('--output', '-o', help='Output filename prefix (for version 1 image), or filename (for version 2 single image)', type=str)
    parser_elf2image.add_argument('--version', '-e', help='Output image version', choices=['1', '2', '3'], default='1')
    parser_elf2image.add_argument(
        # kept for compatibility
        # Minimum chip revision (deprecated, consider using --min-rev-full)
        "--min-rev",
        "-r",
        # In v3 we do not do help=argparse.SUPPRESS because
        # it should remain visible.
        help="Minimal chip revision (ECO version format)",
        type=int,
        choices=range(256),
        metavar="{0, ... 255}",
        default=0,
    )
    parser_elf2image.add_argument(
        "--min-rev-full",
        help="Minimal chip revision (in format: major * 100 + minor)",
        type=int,
        choices=range(65536),
        metavar="{0, ... 65535}",
        default=0,
    )
    parser_elf2image.add_argument(
        "--max-rev-full",
        help="Maximal chip revision (in format: major * 100 + minor)",
        type=int,
        choices=range(65536),
        metavar="{0, ... 65535}",
        default=65535,
    )
    parser_elf2image.add_argument('--secure-pad', action='store_true',
                                  help='Pad image so once signed it will end on a 64KB boundary. For Secure Boot v1 images only.')
    parser_elf2image.add_argument('--secure-pad-v2', action='store_true',
                                  help='Pad image to 64KB, so once signed its signature sector will start at the next 64K block. '
                                  'For Secure Boot v2 images only.')
    parser_elf2image.add_argument('--elf-sha256-offset', help='If set, insert SHA256 hash (32 bytes) of the input ELF file at specified offset in the binary.',
                                  type=arg_auto_int, default=None)
    parser_elf2image.add_argument('--use_segments', help='If set, ELF segments will be used instead of ELF sections to genereate the image.',
                                  action='store_true')
    parser_elf2image.add_argument('--flash-mmu-page-size', help="Change flash MMU page size.", choices=['64KB', '32KB', '16KB'])
    parser_elf2image.add_argument(
        "--pad-to-size",
        help="The block size with which the final binary image after padding must be aligned to. Value 0xFF is used for padding, similar to erase_flash",
        default=None,
    )
    add_spi_flash_subparsers(parser_elf2image, allow_keep=False, auto_detect=False)

    subparsers.add_parser(
        'read_mac',
        help='Read MAC address from OTP ROM')

    subparsers.add_parser(
        'chip_id',
        help='Read Chip ID from OTP ROM')

    parser_flash_id = subparsers.add_parser(
        'flash_id',
        help='Read SPI flash manufacturer and device ID')
    add_spi_connection_arg(parser_flash_id)

    parser_read_status = subparsers.add_parser(
        'read_flash_status',
        help='Read SPI flash status register')

    add_spi_connection_arg(parser_read_status)
    parser_read_status.add_argument('--bytes', help='Number of bytes to read (1-3)', type=int, choices=[1, 2, 3], default=2)

    parser_write_status = subparsers.add_parser(
        'write_flash_status',
        help='Write SPI flash status register')

    add_spi_connection_arg(parser_write_status)
    parser_write_status.add_argument('--non-volatile', help='Write non-volatile bits (use with caution)', action='store_true')
    parser_write_status.add_argument('--bytes', help='Number of status bytes to write (1-3)', type=int, choices=[1, 2, 3], default=2)
    parser_write_status.add_argument('value', help='New value', type=arg_auto_int)

    parser_read_flash = subparsers.add_parser(
        'read_flash',
        help='Read SPI flash content')
    add_spi_connection_arg(parser_read_flash)
    parser_read_flash.add_argument('address', help='Start address', type=arg_auto_int)
    parser_read_flash.add_argument('size', help='Size of region to dump', type=arg_auto_int)
    parser_read_flash.add_argument('filename', help='Name of binary dump')
    parser_read_flash.add_argument('--no-progress', '-p', help='Suppress progress output', action="store_true")

    parser_verify_flash = subparsers.add_parser(
        'verify_flash',
        help='Verify a binary blob against flash')
    parser_verify_flash.add_argument('addr_filename', help='Address and binary file to verify there, separated by space',
                                     action=AddrFilenamePairAction)
    parser_verify_flash.add_argument('--diff', '-d', help='Show differences',
                                     choices=['no', 'yes'], default='no')
    add_spi_flash_subparsers(parser_verify_flash, allow_keep=True, auto_detect=True)

    parser_erase_flash = subparsers.add_parser(
        'erase_flash',
        help='Perform Chip Erase on SPI flash')
    add_spi_connection_arg(parser_erase_flash)

    parser_erase_region = subparsers.add_parser(
        'erase_region',
        help='Erase a region of the flash')
    add_spi_connection_arg(parser_erase_region)
    parser_erase_region.add_argument('address', help='Start address (must be multiple of 4096)', type=arg_auto_int)
    parser_erase_region.add_argument('size', help='Size of region to erase (must be multiple of 4096)', type=arg_auto_int)

    parser_merge_bin = subparsers.add_parser(
        'merge_bin',
        help='Merge multiple raw binary files into a single file for later flashing')

    parser_merge_bin.add_argument('--output', '-o', help='Output filename', type=str, required=True)
    parser_merge_bin.add_argument('--format', '-f', help='Format of the output file', choices='raw', default='raw')  # for future expansion
    add_spi_flash_subparsers(parser_merge_bin, allow_keep=True, auto_detect=False)

    parser_merge_bin.add_argument('--target-offset', '-t', help='Target offset where the output file will be flashed',
                                  type=arg_auto_int, default=0)
    parser_merge_bin.add_argument('--fill-flash-size', help='If set, the final binary file will be padded with FF '
                                  'bytes up to this flash size.', action=FlashSizeAction)
    parser_merge_bin.add_argument('addr_filename', metavar='<address> <filename>',
                                  help='Address followed by binary filename, separated by space',
                                  action=AddrFilenamePairAction)

    subparsers.add_parser('get_security_info', help='Get some security-related data')

    subparsers.add_parser('version', help='Print esptool version')

    # internal sanity check - every operation matches a module function of the same name
    for operation in subparsers.choices.keys():
        assert operation in globals(), "%s should be a module function" % operation

    argv = expand_file_arguments(argv or sys.argv[1:])

    args = parser.parse_args(argv)
    print('esptool.py v%s' % __version__)

    # operation function can take 1 arg (args), 2 args (esp, arg)
    # or be a member function of the ESPLoader class.

    if args.operation is None:
        parser.print_help()
        sys.exit(1)

    # Forbid the usage of both --encrypt, which means encrypt all the given files,
    # and --encrypt-files, which represents the list of files to encrypt.
    # The reason is that allowing both at the same time increases the chances of
    # having contradictory lists (e.g. one file not available in one of list).
    if args.operation == "write_flash" and args.encrypt and args.encrypt_files is not None:
        raise FatalError("Options --encrypt and --encrypt-files must not be specified at the same time.")

    operation_func = globals()[args.operation]

    if PYTHON2:
        # This function is depreciated in Python3
        operation_args = inspect.getargspec(operation_func).args
    else:
        operation_args = inspect.getfullargspec(operation_func).args

    if operation_args[0] == 'esp':  # operation function takes an ESPLoader connection object
        if args.before != "no_reset_no_sync":
            initial_baud = min(ESPLoader.ESP_ROM_BAUD, args.baud)  # don't sync faster than the default baud rate
        else:
            initial_baud = args.baud

        if args.port is None:
            ser_list = get_port_list()
            print("Found %d serial ports" % len(ser_list))
        else:
            ser_list = [args.port]
        esp = esp or get_default_connected_device(ser_list, port=args.port, connect_attempts=args.connect_attempts,
                                                  initial_baud=initial_baud, chip=args.chip, trace=args.trace,
                                                  before=args.before)

        if esp is None:
            raise FatalError("Could not connect to an Espressif device on any of the %d available serial ports." % len(ser_list))

        if esp.secure_download_mode:
            print("Chip is %s in Secure Download Mode" % esp.CHIP_NAME)
        else:
            print("Chip is %s" % (esp.get_chip_description()))
            print("Features: %s" % ", ".join(esp.get_chip_features()))
            print("Crystal is %dMHz" % esp.get_crystal_freq())
            read_mac(esp, args)

        if not args.no_stub:
            if esp.secure_download_mode:
                print("WARNING: Stub loader is not supported in Secure Download Mode, setting --no-stub")
                args.no_stub = True
            elif not esp.IS_STUB and esp.stub_is_disabled:
                print("WARNING: Stub loader has been disabled for compatibility, setting --no-stub")
                args.no_stub = True
            else:
                esp = esp.run_stub()

        if args.override_vddsdio:
            esp.override_vddsdio(args.override_vddsdio)

        if args.baud > initial_baud:
            try:
                esp.change_baud(args.baud)
            except NotImplementedInROMError:
                print("WARNING: ROM doesn't support changing baud rate. Keeping initial baud rate %d" % initial_baud)

        # override common SPI flash parameter stuff if configured to do so
        if hasattr(args, "spi_connection") and args.spi_connection is not None:
            if esp.CHIP_NAME != "ESP32":
                raise FatalError("Chip %s does not support --spi-connection option." % esp.CHIP_NAME)
            print("Configuring SPI flash mode...")
            esp.flash_spi_attach(args.spi_connection)
        elif args.no_stub:
            print("Enabling default SPI flash mode...")
            # ROM loader doesn't enable flash unless we explicitly do it
            esp.flash_spi_attach(0)

        # XMC chip startup sequence
        XMC_VENDOR_ID = 0x20

        def is_xmc_chip_strict():
            id = esp.flash_id()
            rdid = ((id & 0xff) << 16) | ((id >> 16) & 0xff) | (id & 0xff00)

            vendor_id = ((rdid >> 16) & 0xFF)
            mfid = ((rdid >> 8) & 0xFF)
            cpid = (rdid & 0xFF)

            if vendor_id != XMC_VENDOR_ID:
                return False

            matched = False
            if mfid == 0x40:
                if cpid >= 0x13 and cpid <= 0x20:
                    matched = True
            elif mfid == 0x41:
                if cpid >= 0x17 and cpid <= 0x20:
                    matched = True
            elif mfid == 0x50:
                if cpid >= 0x15 and cpid <= 0x16:
                    matched = True
            return matched

        def flash_xmc_startup():
            # If the RDID value is a valid XMC one, may skip the flow
            fast_check = True
            if fast_check and is_xmc_chip_strict():
                return  # Successful XMC flash chip boot-up detected by RDID, skipping.

            sfdp_mfid_addr = 0x10
            mf_id = esp.read_spiflash_sfdp(sfdp_mfid_addr, 8)
            if mf_id != XMC_VENDOR_ID:  # Non-XMC chip detected by SFDP Read, skipping.
                return

            print("WARNING: XMC flash chip boot-up failure detected! Running XMC25QHxxC startup flow")
            esp.run_spiflash_command(0xB9)  # Enter DPD
            esp.run_spiflash_command(0x79)  # Enter UDPD
            esp.run_spiflash_command(0xFF)  # Exit UDPD
            time.sleep(0.002)               # Delay tXUDPD
            esp.run_spiflash_command(0xAB)  # Release Power-Down
            time.sleep(0.00002)
            # Check for success
            if not is_xmc_chip_strict():
                print("WARNING: XMC flash boot-up fix failed.")
            print("XMC flash chip boot-up fix successful!")

        # Check flash chip connection
        if not esp.secure_download_mode:
            try:
                flash_id = esp.flash_id()
                if flash_id in (0xffffff, 0x000000):
                    print('WARNING: Failed to communicate with the flash chip, read/write operations will fail. '
                          'Try checking the chip connections or removing any other hardware connected to IOs.')
            except Exception as e:
                esp.trace('Unable to verify flash chip connection ({}).'.format(e))

        # Check if XMC SPI flash chip booted-up successfully, fix if not
        if not esp.secure_download_mode:
            try:
                flash_xmc_startup()
            except Exception as e:
                esp.trace('Unable to perform XMC flash chip startup sequence ({}).'.format(e))

        if hasattr(args, "flash_size"):
            print("Configuring flash size...")
            detect_flash_size(esp, args)
            if args.flash_size != 'keep':  # TODO: should set this even with 'keep'
                esp.flash_set_parameters(flash_size_bytes(args.flash_size))
                # Check if stub supports chosen flash size
                if esp.IS_STUB and args.flash_size in ('32MB', '64MB', '128MB'):
                    print("WARNING: Flasher stub doesn't fully support flash size larger than 16MB, in case of failure use --no-stub.")

        if esp.IS_STUB and hasattr(args, "address") and hasattr(args, "size"):
            if args.address + args.size > 0x1000000:
                print("WARNING: Flasher stub doesn't fully support flash size larger than 16MB, in case of failure use --no-stub.")

        try:
            operation_func(esp, args)
        finally:
            try:  # Clean up AddrFilenamePairAction files
                for address, argfile in args.addr_filename:
                    argfile.close()
            except AttributeError:
                pass

        # Handle post-operation behaviour (reset or other)
        if operation_func == load_ram:
            # the ESP is now running the loaded image, so let it run
            print('Exiting immediately.')
        elif args.after == 'hard_reset':
            esp.hard_reset()
        elif args.after == 'soft_reset':
            print('Soft resetting...')
            # flash_finish will trigger a soft reset
            esp.soft_reset(False)
        elif args.after == 'no_reset_stub':
            print('Staying in flasher stub.')
        else:  # args.after == 'no_reset'
            print('Staying in bootloader.')
            if esp.IS_STUB:
                esp.soft_reset(True)  # exit stub back to ROM loader

        if not external_esp:
            esp._port.close()

    else:
        operation_func(args)


def get_port_list():
    if list_ports is None:
        raise FatalError(
            "Listing all serial ports is currently not available. "
            "Please try to specify the port when running esptool.py or update "
            "the pyserial package to the latest version"
        )
    port_list = sorted(ports.device for ports in list_ports.comports())
    if sys.platform == "darwin":
        port_list = [
            port
            for port in port_list
            if not port.endswith(("Bluetooth-Incoming-Port", "wlan-debug", "debug-console"))
        ]
    return port_list

def expand_file_arguments(argv):
    """ Any argument starting with "@" gets replaced with all values read from a text file.
    Text file arguments can be split by newline or by space.
    Values are added "as-is", as if they were specified in this order on the command line.
    """
    new_args = []
    expanded = False
    for arg in argv:
        if arg.startswith("@"):
            expanded = True
            with open(arg[1:], "r") as f:
                for line in f.readlines():
                    new_args += shlex.split(line)
        else:
            new_args.append(arg)
    if expanded:
        print("esptool.py %s" % (" ".join(new_args[1:])))
        return new_args
    return argv


class FlashSizeAction(argparse.Action):
    """ Custom flash size parser class to support backwards compatibility with megabit size arguments.

    (At next major relase, remove deprecated sizes and this can become a 'normal' choices= argument again.)
    """
    def __init__(self, option_strings, dest, nargs=1, auto_detect=False, **kwargs):
        super(FlashSizeAction, self).__init__(option_strings, dest, nargs, **kwargs)
        self._auto_detect = auto_detect

    def __call__(self, parser, namespace, values, option_string=None):
        try:
            value = {
                '2m': '256KB',
                '4m': '512KB',
                '8m': '1MB',
                '16m': '2MB',
                '32m': '4MB',
                '16m-c1': '2MB-c1',
                '32m-c1': '4MB-c1',
            }[values[0]]
            print("WARNING: Flash size arguments in megabits like '%s' are deprecated." % (values[0]))
            print("Please use the equivalent size '%s'." % (value))
            print("Megabit arguments may be removed in a future release.")
        except KeyError:
            value = values[0]

        known_sizes = dict(ESP8266ROM.FLASH_SIZES)
        known_sizes.update(ESP32ROM.FLASH_SIZES)
        if self._auto_detect:
            known_sizes['detect'] = 'detect'
            known_sizes['keep'] = 'keep'
        if value not in known_sizes:
            raise argparse.ArgumentError(self, '%s is not a known flash size. Known sizes: %s' % (value, ", ".join(known_sizes.keys())))
        setattr(namespace, self.dest, value)


class SpiConnectionAction(argparse.Action):
    """ Custom action to parse 'spi connection' override. Values are SPI, HSPI, or a sequence of 5 pin numbers separated by commas.
    """
    def __call__(self, parser, namespace, value, option_string=None):
        if value.upper() == "SPI":
            value = 0
        elif value.upper() == "HSPI":
            value = 1
        elif "," in value:
            values = value.split(",")
            if len(values) != 5:
                raise argparse.ArgumentError(self, '%s is not a valid list of comma-separate pin numbers. Must be 5 numbers - CLK,Q,D,HD,CS.' % value)
            try:
                values = tuple(int(v, 0) for v in values)
            except ValueError:
                raise argparse.ArgumentError(self, '%s is not a valid argument. All pins must be numeric values' % values)
            if any([v for v in values if v > 33 or v < 0]):
                raise argparse.ArgumentError(self, 'Pin numbers must be in the range 0-33.')
            # encode the pin numbers as a 32-bit integer with packed 6-bit values, the same way ESP32 ROM takes them
            # TODO: make this less ESP32 ROM specific somehow...
            clk, q, d, hd, cs = values
            value = (hd << 24) | (cs << 18) | (d << 12) | (q << 6) | clk
        else:
            raise argparse.ArgumentError(self, '%s is not a valid spi-connection value. '
                                         'Values are SPI, HSPI, or a sequence of 5 pin numbers CLK,Q,D,HD,CS).' % value)
        setattr(namespace, self.dest, value)


class AddrFilenamePairAction(argparse.Action):
    """ Custom parser class for the address/filename pairs passed as arguments """
    def __init__(self, option_strings, dest, nargs='+', **kwargs):
        super(AddrFilenamePairAction, self).__init__(option_strings, dest, nargs, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        # validate pair arguments
        pairs = []
        for i in range(0, len(values), 2):
            try:
                address = int(values[i], 0)
            except ValueError:
                raise argparse.ArgumentError(self, 'Address "%s" must be a number' % values[i])
            try:
                argfile = open(values[i + 1], 'rb')
            except IOError as e:
                raise argparse.ArgumentError(self, e)
            except IndexError:
                raise argparse.ArgumentError(self, 'Must be pairs of an address and the binary filename to write there')
            pairs.append((address, argfile))

        # Sort the addresses and check for overlapping
        end = 0
        for address, argfile in sorted(pairs, key=lambda x: x[0]):
            argfile.seek(0, 2)  # seek to end
            size = argfile.tell()
            argfile.seek(0)
            sector_start = address & ~(ESPLoader.FLASH_SECTOR_SIZE - 1)
            sector_end = ((address + size + ESPLoader.FLASH_SECTOR_SIZE - 1) & ~(ESPLoader.FLASH_SECTOR_SIZE - 1)) - 1
            if sector_start < end:
                message = 'Detected overlap at address: 0x%x for file: %s' % (address, argfile.name)
                raise argparse.ArgumentError(self, message)
            end = sector_end
        setattr(namespace, self.dest, pairs)


# Binary stub code (see flasher_stub dir for source & details)
ESP8266ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
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\
""")))
ESP32ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
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\
""")))
ESP32S2ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
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\
""")))
ESP32S3ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
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\
""")))
ESP32C3ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
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\
""")))
ESP32C5ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
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\
/wN+6o5D\
""")))
ESP32C6ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
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\
zS/O90QgYXj/EjPboqSeTuM0j5S6+B9Q0b8a\
""")))
ESP32C61ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
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\
""")))
ESP32H2ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
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\
""")))
ESP32C2ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
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\
6adu0+5VbVYJORJu94WjojzJjbr9P483Uh4=\
""")))
ESP32P4ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
eNrFXGt7FDey/isGB3M5bFaavqkTMB4y9jAGx2RPgMAOG7rV3UD24CxeczCb9f72o7eq1FKP5+Lss89zPmC7L5JKpbq8dWl+u3nWnp/d/Garvjmen2s9P6+L+c356dPr83Ob7rgfo0P3Q+HZdH6ucneR00vnKp2f\
d/nx/Lwx7ma9Oz83ZeJ+uNstHrsx/hqv4lrbPXfTLWJq97vkF+vR3vWJuxy5H2o0c2QovDFy/9wQldyYn8lsGK2TT27ZzN3p+KXSTWEbIUn3ezivcG2ffs8EG0dJ5RY0RBm25P46ow1gk9WfsF3ZX4u920C9pZmx\
vwrru2FCkFFEEKZJH7i/SkzLJJ/IG4ljJr194Z6nS8lv3Q03qpE9dKO9ejLYwrb7y8jumtHk4Qw8m113m1BZFTgFcpUwXoF8Nb6DDbs/tZFFQVKGc8zAFkys+EKpL8/CVCY7sDxZk9Oos307P3Vv09VF/+ZDHuxX\
rtX8dIzRlvh03oEavFhOcXpuSc10YHN4gdjtBuH9TBiNnYDpxPDs8vYaBUraBNLES3TWD5FZMyYljK2LDK8ei4jTwWb8r+68VH98YI+EGSmGFDRE3i5kh/idyMngn2HRavIpX2B946bTxKltiLXsC3fLYpt3WPlz\
wthCxpb67XA1lYIxlWekrE86p/1hy80KY+uK1YEozAOFPEpGlkIhNl3XWMBxoPXkYhiTK8LR+AtshCe8xk+68gWdwwmfKU7BqfJAfWXCJp6wFaJY3gv/9Knfk0intt+5NRs2FTQ/mGCv+q6nQE7c262ufBCvSMeZ\
y1GY7R3Z4ShIm5Vr6K6FzKVuqc4t1Tm1NeY72jPI2Q8rgyRTDhixQIYtH1wEjRdy/KHDqJSGlyvNdxc86SJry4/OSjXWkdxUh7DBzoI16XNYCF6nab9n9a1gI9KvQRNGpuNDkRIFs82z41CgKC3OFW9lh/axGGC6\
9bT+EVP/+PAlSHl5/RUE4tW1yPxUpOj2v9lM0uR6xowsixJ3rj3ahZWF8R3tiJRDO8xz5gpdwProRwvWDA8wfa4PoCb74PF+tAsb72LrNwxN0/H37GNsC/NwBFX/95lGBJ0EclYxkCS8Bn2/k4E3HvQsBE2Bi2Xi\
3Y2XS2En3BZkkFi5y6xTy1hX6YNZxDe4Omy8Z3kaOLyco9jW31ft+Q2sx4DVwv7XkO4vxPG0YB4G0+VBQX5IFt2ZrNtyR9SkyXFKI0u0nc1PLrKX4uebKURkYumgbsqIdMJqacRv1ynrLOht4Fuq5r7ouzehsNuW\
TIhi32G71edKyqEvYGzMhNh4B2y8s5yNLMmjyGf449Ai3nRQ8D/W2B+Cp2wBsipIuXePhhxZuUbc/7penZtmPL3PgrlEMIZ+2P0k72zn83U09cK4mqq9d6upojMhHZnCdj9i2TEde3QgKG0nwZvRTXjk0dPrP0Jr\
fsTqL/dXQZ/FjWm52ZYCPOxk4USwElxiLSdGoqyCe2CigeAgO0Rr5EXm3jPIb+s9RMcC29j3Q3QagcwdVuJOv7DsYQmlpTG67qG2XdQdwQ9VJrK/it9WHdupQD3VA8yG8HYMIAeTqezgf8QALZ1263uB8wquD+pD\
4FJsSCe87hrGCOSdGSX8Td4s90VP8lVL7B2Ppgs6O0BHiiE3Xi5TggIHHgl6OGM8+lDiU4uLZWcxP/22YL/dpce0bc2IdKXJg4UmH1F4X9T4aGbKZJL6FFu7TE1Vfjtw9iDHby4HF1Ug4BkrA9OLGffXUsOy2ugk\
G5zx4HBDbEcUEy89GBnwNCe13Bbz4bmcMN02izmJN9+KUkD5IfxWnpCSNN/ARDCf8Lsm4zc/fctm2tbb/IwPM8nFhSmv+nJ+liMLJ5o+xupx/lOOdBax0cuP7EuHfoeQ6IidlG2/Zj9PApKzFsIP0Qs2ulfxppqW\
mdWKpQdghqVv8Vyd8AskEOWih1tvnjFJPXo2gT/rEmYURQjAl8D/2BImghl0XhJKq3bYRukEPrH0sfUj6ySnU/5yYn/mgwAJVaMjxLncB/rZLXsmvITAsU5A8VdiKgVlQxSAc1YqSN3yUoLYt/lEVJFuYAf2Zirn\
Etus4Fd6pC4XIm7htr9wgnwqDEjkEDCiTkXG6ULEmTZp/RNIIy4c7PUheimzuD23DY05FS7hUNruiPnRNVOgjWQqJgVDmu/w5nh+WkIhb5BV5UCzTD7L1Hp8hC2yXpXJi9d721vuEUhUv4jcQwKyv7BIrOSz06Kt\
u5iQw6s502GzXWFOTsypoHN6GqI/k2fzs4M4jsSq9iHY0npNhzWtomzOcivNYItd8B5xFh7RvEfWIkhSI2F/KwRgcNfusqatQ9O1juO+evRi+9YLn3PARorMbe50xVbyYLRoYS0L2wXCOnkuRryr1tNUtdf49ECF\
Lu6L0YWcMBI/ZJM6xCXPF2OdCDEGULiA1tdhcnNJxaoXGYUpVTVm21SWv0imjSilYH21T8fAO+uPhFauRs/+ANQyn+P0c5jh/CVbWDduToZ8DiCRz7pDybV0dD/dAYTLEQvlhwePMfrxzhPceoJJjuC6XoNwLXkM\
Xv8tiPkOeZOdWDlk7rVHlbHDAKMcpf3yRLDQt4GUHh8RZiDctjqegRC9ZWMHstjABifGeINgHyUhKT1JyUcIxugV+0ACoDVQGjnyYdKvREZWjR6TgwecSVY4D9l8ZNmRD6x+p/PANDrd6DxMcmci0L6U3EXCM0CZ\
kO3UfSCr3cGeIUGy0qqVSEx1Fk4nkRNvKC3xXKImfW+NEDujBcG8JI6xHMY4eBVzw9HrJq+8CScfj5wvafkiZbRo+fIevwlemNJHGo8JtLwUT0oXd3Bh22/xiyzjV+OLYX6UGSaJSXjc5l7IQmtyZ7+J5+gEeHfL\
WLbSelOMFdLSM6Z6mT2vi4U81jrFI3eL2IAMrSaU9p5xLEFVnbGXXJ0lW4cTiKkLs3+4wuxU1ojDq8WIqpdwCrfUIx8WTSXGolObhDzFakLfSPJ1tLd9y89/fbJ6w/sPxHeXG4KeEpklVFFs8unBrOA5CBQjpgpg\
mKLVRCJMNqFOq4ouMMIvTXUeGIeUpmt8HmAdEeZxcMI6TtzXMX73IZIacrqTTI9Ng98mcu1tuCrUgyivWo56hpGbvh5kuVN+Zz3DvzjIeBrRnsa0R2dMGftiIplawQFWgn8w0iTbDH06GUUppUKCOgEStli+pxa5\
iqaQGfzTUOVaJ/J6UMOR7H+bRQzsaxtl8yDc4uRNOPo6LrIUfghhgJonpPx1U4QpuK7C1ZkgITvCGKLvDrOxlk3XHiTqgo+e9Gf5PkVb+7wFpTmOHjC4rotPSBPabEeiyJbjKdivRoIxBGJERXEYRYBa1lCXrzmD\
y4gnP4YGmq+ZfpP9st50yUmc+ISvpGC1yClCnxQTqrtSuFkTl9vsls8w7v9AGk5Gq+YSUUnZpz24zrKazE9mIPZl9wp7fjXrHdB1yQtDm31eWGXvIajTQyloBlS0I0oiKc22Y2VpUBQZvnlrHf17khWt+pzuV2MJ\
6pbrH/59HviSL4waWMQI/XyI5DLzcv4FspSRCDQARAUAUfaK129FCOjw4dlsDQkon7OsNCIrm8SB7hkfo0MSKNteA7DZ7TuiwlQnTSjHIPkYyuKqdYFuteA0hv5iZc68xgG8RSzZvoW63eprdSfebK3xfzXqzL6+\
4kSirzf/F0BjadsvVFVtq8diICgWrZLLuVKfUenT1LTh3fXImoqqWfBVbBLujC3KBLXgwErULRGtpbwFhI84n30firCYnsX0VwGy+gFDKZORyX9J6aNiMH6T8NaJR2OEeO2/ZhHwKr6M2R62WlJiDT+tzGrxbtW7\
gXi/R/S4fTfIjtHE/T+7adhkyH0Wdx0kabnyvOgTD/sYWN6VyFUUGPgOTOWgU8STsuOjYeGyLgSKexPgBG3Bgxc9PCaDUhbD5z6pHq7FmaNw3fmwHlGBD511+4lRaIk0Qyv5lo5w9mZb6RSiqj/cJysp9tLp4dF9\
cEGTT29+v5Z5MbySJrO1xrsD49xVe78gSKgmhwgSqtkdBAkudjt5DC39M6KJ07gSEbDzFVXMp8rr4sV4ln0MfO8kyCSPwdaPLGQwgcFWkjEUg+ktojecrXhPhLJo1WnxPN/ll1YJo1UosmMzZD0yhHkNZ9zIWj0d\
4jZK8SL32/meksI3FNgYM7pJYLPTY59r7kt0nHdCWn04x2iAQ5c2ZfTYSK6tog6FASV8mkoSUK3P86D3piF7s/+O/YPKQGCT+ENZAn+53+IXznGWlaxDYS4b8LO4dIMZsuM4cFQLyqX8hjuJFLty14qUIJSp4gqQ\
Sm5Ihca3mvj4kioq6zQBeNJJmbtonwYKrECakpoZ6Fy2fKfQflyKSPjwT+OjJwGXND6W0vn+/nps5ZE09fsobIhq+tSRQ0M3TpBe1TMTJO3ZVfsCS38YiNazbzdAwSyeY23mOtn85hvJ9/eC6+tAOnkbRVG+8ONf\
w3EZ8zP8y74YbCdfH3Hk1aWYd5VObz2VUq7K9nclA2IlKWRhDoZpSMoWq0ulXzfvmU9OjqTdTdo2lucp37DtNsiQt1SpH5ND6kSAi8+shl4ufP+STvBE6UhiipBfMlAZ2FyvMnHgpKOKMLU9deH0OYNPRrXgKoC3\
ZYz28/npX9dZxfE1jPoToxwjnWCWVN+KuaYTk4epf0h9d9wOdSLNUOBbp5kcnyaUloUzvKoTzzGCE8P3KX18NJV0Pame+oEurb+8jcuyDfl7XiSqHFuq6ihfmvGspV5Py9nEPvePinyJ0jaMHpXjEbdWEAQSAgDC\
ZlcWydN4xXiRnCMCEE3tblQ4Rosiuo4aYV0c6F7cG0a5bXQNtVPt0b0SucS60Pduez+7zEwxaGY4tO+tzLJTVuqfC+YislFejNZPcNH30UrjLOl0vcRyXR6/98/XXGfbQAJSJ9lKKt78Y9BDCu89XYi7RpHdAYsa\
sTsE6rsod11GFRQjeqUGe+FS7dl6gKvU+fwsOl5FaGfFy5XiRNTKJG+dS3staXFfP1e+WQdjayqq2Q3lq6raUO5oBYSt4PTWBZ+XLb3aejXVgu2G6u309G1or1HZFDLZ9f0os5BW6lG/ZlsCa6eL0F9Ag7oZAe53\
cqvtMZKR2nrfK2lV6KohXSbUWnhLLLaLjO9nPznk9wDzv2ck2dkhQvUxRyBnfjq1v8pFuoIYAWrZCnpC8nnk+2JyzoUZqZvpZuIPJftG/mobspD30Opzb2CbqPn6dvrJJ+koEpwwJgRABYQCPPb1D0P+Te+vC9YE\
LmrBCJwTnmU8YUP0iF1sspGs52uN9DZl4apNGpCkoavDB0GVD7Fg3Ts5FOU73MX2WoUkKvTbA8RGrDykE6fDceUxPPYX3L0ujVjZEwlZUjkrU+5FUad0z3CelNdsu/EHGWj1BaTbNPBz7s6R9HSSBsyo0aOf1Aax\
UO03nOfzwS5+V2qdKwbaHL1AkxVc1uo2vBjVXKlRjNra1jWYYtww92vU4vXr2IbOxANSzn5ho1XHvfFrJW30/7JR9rCl3bRX3llNkO5Z1Ma/0g9gRx9YHXgmVJCTJO2fn8V2c0FquExvu2V8zNfzUdn/KB9t6M3c\
zMX8hCKSs4hRXpXWWQBFyfC+qQhFpeS1T6JuZPaW9MAgv9/MeOneeoALsB7U/B+7Hf8FCQwFBUEYQcankws2YEmwzbB1FhjRoD3Wnwn14ZsZu0fvJWqC5OPIhPmWjNI8IlgICGul6ajBcjSptXQoB+KAOqmNlupJ\
WBCetC6lTmH02oWrqNcDU2u3MDlRdCybSVg1EQch3q7hyGgtHfhd5wsNdwuNdqdvF9Ij7AqJ+G3y9zeBsstQzVk1k4B5P5MNHhYuqqRtaM5pDY/Yht4+dhmPJfCLwj1nmi37uMa3w9JqP8ZxxCQCL4vBBL+B9Cp9\
L1S85ts8i0DGdjBGPkrxPp8zrimjkZjDXRF3a3VxDrkIbxaddBwlYftoLxiCstkUbbo0Y+XiL7z+m4hNxfney8DrPr3W+tfWY518KdbxSKqPyqZystpXJsGR9n1IR11RCD4wlnWoX7ipZKvukKW9s8+MQcRqyg7Q\
Z2Mi05Q+RD+MeYLEHFQT5fCg5evMVkfFwjJGL0YMCMMvGBAv1+XQpKRMQCOZEvqUCimQzvwFqOmz77TCmO4CAvODiBSo6qRbczA0/uiJstDmIaG8eDSFaKOlAw/6URsH1CCyE9GntGbH4rYu20ocM4IPdSRmeYi8\
SjmxVsrRjT0IqQ8yd2mvhBevMeaTbyR6tOGw0Iyv7eQnfMik9i5EBY2PHmE60oe8qhXhxxQdtdOIOmthhnM1Z2NWskbiSDpeSsHVl9yH4U0CplOKoTGPtjni4uYjMZEtXbxn7vgP8Ixkp3V0uF0nPZsepbYD3wb3\
aT+w5PXZG5pGEuXW27iG1ZiIlLkbMRr0jZysTZGCIcVBRc97Y1//oKzFSD5OQ7cjdUVU4tIXtscBby0lKqoN+DyKOfINQyFS9AlthOQExgFB2jJy8pdUig7I56U89+RjB28aGScxlWeBRvrTV88CQ7cYKVTSc+An\
0YIgjHivAbzgFf7AznnwpORhp/yIzecWFTJ9Wkv1TRJ7vqOhFGkuJelms2XZJ+2/+ZQujWrkYZHgSemxj/0LEmCkkqMQXlk/uZpE/saW4ZNU+iLWXjXTsSUdM4NUjX08+EJlHJxPk0mnsf8c05saaswuw35YhG4w\
4RTK1gnvxmThE7ZVQNkjAxJxtbs+DLPoF4FvW+YkPD9BYzuaMTP/c8cEr08fBzTRzFfKcZbS76vEmnEuyVY+AyBCRcnn16JxjT8sQ55ebBDqUtQ7A6/sM7ake33buel1jD8el88uWNZVztb2NPpmvCeELHgCP8yh\
Edo0aX7jg5O/SR67HH7kxbqEzoauGn7qpJJbTFatghVUUrVHddCCcbUhgnRwmrXPqZd7ItZG0sH5wxCLIdjpPykeTD76qRCz5j/HMFlIz7XyNUapht1Ovj9rnQOjflz6BJt4N9hbFvZWy5F3zR7bWlKclu1jnU+3\
v2IrXivf6YRnmVTnas8h/TlY6DIbsz0nXEfx/Y1QnnP0nzL/+lxLlch01CahRXKLyHykbNKHYhDnXo0Jp2z8x/7+CwMbBWb+5d5MuTP9XQnYOtvwvPp1iLEp6YTlfZ3F9Hv/I0dEV7IqRg6LzFQqa1A6Jb1aSR7S\
OD9AnJy/jurzN+9u0f938fPfz6pT/K8XOkl1muWJSd2T9uTs9Et/02FX3Gyqs4r+e4w3UpuF7IJeTT0KxynjDcrRNyq6gF/XI7nQ0udIF/DC/RMlcY27eBfdRhtKf9HaaF58bIEiSZh3tOxJlfckcnFlE70ojsg7\
d3uS3vR/ySe1fkYsqrPLM5pon418N+8ufuLewmMJ6oY3/93f/9uvFU2vlhNwU45ycPJZaYqRuvg/XQIDTg==\
""")))
ESP32P4RC1ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
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\
""")))

def _main():
    try:
        main()
    except FatalError as e:
        print('\nA fatal error occurred: %s' % e)
        sys.exit(2)


if __name__ == '__main__':
    _main()
