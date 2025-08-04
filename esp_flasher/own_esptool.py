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


__version__ = "3.5.0"

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

SUPPORTED_CHIPS = ['esp8266', 'esp32', 'esp32s2', 'esp32s3', 'esp32c2', 'esp32c3', 'esp32c5', 'esp32c6', 'esp32h2', 'esp32p4']


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

# Function to return nth byte of a bitstring
# Different behaviour on Python 2 vs 3
if PYTHON2:
    def byte(bitstr, index):
        return ord(bitstr[index])
else:
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

        try:
            print('Detecting chip type...', end='')
            chip_magic_value = detect_port.read_reg(ESPLoader.CHIP_DETECT_MAGIC_REG_ADDR)

            for cls in [ESP8266ROM, ESP32ROM, ESP32S2ROM, ESP32S3ROM, ESP32P4ROM, 
                        ESP32C3ROM, ESP32C5ROM, ESP32C6ROM, ESP32C2ROM, ESP32H2ROM]:
                if chip_magic_value in cls.CHIP_DETECT_MAGIC_VALUE:
                    inst = cls(detect_port._port, baud, trace_enabled=trace_enabled)
                    inst = check_if_stub(inst)
                    inst._post_connect()
                    inst.check_chip_id()
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
                                ESP32C3ROM, ESP32H2ROM, ESP32C2ROM, ESP32C5ROM, ESP32C6ROM]:
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
                             ESP32C6ROM, ESP32H2ROM, ESP32C2ROM, ESP32P4ROM,)) and not self.IS_STUB:
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
        if isinstance(self, (ESP32S2ROM, ESP32S3ROM, ESP32C3ROM, ESP32C5ROM, ESP32C6ROM, ESP32H2ROM, ESP32C2ROM, ESP32P4ROM)) and not self.IS_STUB:
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

    @esp32s3_or_newer_function_only
    def get_chip_id(self):
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
                             ESP32C6ROM, ESP32H2ROM, ESP32C2ROM, ESP32P4ROM,)) and not self.IS_STUB:
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
        except NotImplementedInROMError:
            pass


class ESP8266ROM(ESPLoader):
    """ Access class for ESP8266 ROM bootloader
    """
    CHIP_NAME = "ESP8266"
    IS_STUB = False

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
        return "%s (revision v%d.%d)" % (self.CHIP_NAME, major_rev, minor_rev)

    def get_chip_features(self):
        return ["WiFi", "BLE"]

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
        features = ["WiFi", "BLE"]

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

    def get_chip_description(self):
        chip_name = {
            0: "ESP32-C6 (QFN40)",
            1: "ESP32-C6FH4 (QFN32)",
        }.get(self.get_pkg_version(), "unknown ESP32-C6")
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        return f"{chip_name} (revision v{major_rev}.{minor_rev})"

    def get_chip_features(self):
        return ["WiFi 6", "BT 5", "IEEE802.15.4"]

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
        print('Hard resetting via RTS pin...')
        self._setRTS(True)  # EN->LOW
        time.sleep(0.1)
        self._setRTS(False)


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
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 4) & 0x03

    def get_chip_description(self):
        chip_name = {
            0: "ESP32-P4",
        }.get(self.get_pkg_version(), "Unknown ESP32-P4")
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        return f"{chip_name} (revision v{major_rev}.{minor_rev})"

    def get_chip_features(self):
        return ["Dual Core + LP Core", "400MHz"]

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
        return ["BT 5", "IEEE802.15.4"]

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
        return ["Wi-Fi", "BLE"]

    def get_minor_chip_version(self):
        num_word = 1
        return (self.read_reg(self.EFUSE_BLOCK2_ADDR + (4 * num_word)) >> 16) & 0xF

    def get_major_chip_version(self):
        num_word = 1
        return (self.read_reg(self.EFUSE_BLOCK2_ADDR + (4 * num_word)) >> 20) & 0x3

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


ESP32P4ROM.STUB_CLASS = ESP32P4StubLoader


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
""")))
ESP32C6ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
eNqtWmtz1EYW/SsGgw2EynaPpFELgj0DMx6M4wRSEAoYiNUtyQtLvNgZF2YT57dvn3tvq6XBHrNV+8EPtfpxn+c+Wn9uLuqzxea9Nbs5np9pPT+z+fys8T9KHVyfn7l0w/8aPPG/FN7P/IuhfxjyRJXOz0w6mp9V\
xg/aLf9UJBian9W0x/wsPGMqnrXz0wt/kLH+b8ET7WB0feIfB/6XGux6UhRmDPyPX6KSm/OF7IbVOjn1NGZ+pOFJhd/CVUKSjnwo5uMnJth4Skp/oKFRsOT/WxADYLL8BewKfzV4d5F6RzuDvxLn+2VCkFFEkH9q\
UiZIF9iZqT6SScl8kxec+/fphRzUfsCvqoSNZjCykx4X6556IwxWg8nDXYht97rnQ2VlFBYoViJ7BQ7U+A549v9qI4eCpAyqzCAZbKz4QakvL+JWJttxvFk1pFWLqZuf+Nn0dN7OfMiLw8lWzU/GWO1IVGxNmFjM\
oEB/pGY6wBwmkMT9IszPRNbgBHInmWdfs1cpUFInMCg+onFhieyaMSlxrc2xUTYSSyfdZvxjy2DYx9tuX4SRYklOS2S2aMMOoF4viKAdw9ZVDWf8gPON306TpNZh2cIXRot8nTksg56wNpe1hT7sn6ZSCKYMgsxZ\
cOR2OihbiCqxFrzAI4jCYaSQzGooKwuhEEzbIQ7wllgHcrGMyRXjqMIDGOENr/GbpnhJejhinUIL3pt7HiwbVt0NayGK7T1nEw8MiWlq98gfWDFU0OZeApvfODMcLsoOqNUU2+1h5FxDUYFZ3xDOBtHKnDzDZx1s\
LfXnNP6cxrurMY+IV9AyjceCHlP0BLBEgyu2z1vOiZbWy6EZw2cV5tE577gsT9qOcDmYQlepKTBUC2IrwTxC35YEAnYnIJZOc//CwQkqiFNPHDn8phypJp4MQ76csiSUervtZ2c5iOyBVADJIdOih9GbCRaVSJxQ\
XbEodc6yM+A0H4puKsf8FUr+uoci+SaqB5CLZxBfWHZ9lQOdvZ5HW+JppbnBrJBk0yujje5oqwYkkZIATPX2R5D3jHGqyEMIYCpg0i1jkHspPpxN2Tg50s2YfnLmfG1LgqnOozWA0lkwzxGGIgEvWFDECm03XUmN\
36tRSSYIryiu9AJGJ+qbgCrBThmEZmI52Wyddw+RXSfs005CSqBJZYfnrFZEUJiykzcNom91z0/NWDz4ayF7zSbm7Dq/YHN6lovdtJD+lIPaskcErVHU7noErWKPoBg/mQTFUvynzMCxugpho6x5PehiF7o9kTeQ\
WrHBaYtOXsGTQ1Lz2L2AqMPjxL1jdtXgVUbO/hhJhhGbMivMB2dSXOvmCEpclC1/RFKYk2DnI0ZXv92cFs8nEtYaGkjbXCImDT0LePbgdz/YLGHUZdTVSrIBQB6OAWVeHadshRq2pkmSKxHQY8eJgI6ARwSwDppU\
wFtI29X54Xxx0I942NEjv2AKg8M5o06Dk5uA74nYPga99CtBGy3meSG+BmJ/l4O8DZ5Mu3O1hFiW0KFETlf1VhNKX2c1kPmkl4uWlF++Esl0s2u24phDm+SlJNVKlJAzStJf8JGsM1Q3aczC28w+YYeDo7QCl7kY\
r/P9bVkeDoyIuUqrupd6StJSZxEtQkpW5/HZUYoWxPoFphh3sjHLs7xVUz/bjos5C+RcchwAIJXQyGTdEW8WEVoix7H6itXsiZUHIXBOuO+Pryl0nx7jtGyDjagacNCiU/MnrAf4elULvToE1K+f2TRuIQ35XjSb\
fbjcUkr1PcmFVqi7kjdeOHn0/S0ednq6T9UD+a1lN0EdZsvRHTBfTuZHu8gQXzWvd1t0uA7Ic39w4cNSeP+EgYxyArOxGs1qMuoL0KyuetvcWsUEOL7N+xQpKfLG+G2nfshA1/Btx3ayWADVBTKbjJRVAfBzFHrZ\
r6I20RCprYEuLXRXvO5EnasUV3zP4kEGTn+HnIgic4QhlggttNp0kqVBzItqvVS3DbZWS5VyapMdgr3BSwh1pfxGqDc0YD/5boK45Ox7/2BduYexY+RIx9scR0x2nc+us+zZtsSsEpxlV+hIqWsSijhGutNdBhvy\
vfz9GIFWf+6MpXfGIfiKdVVUn/RO/ekqUfjN6p6BvUC8Xb8rqIbaTE++vPH7JZzw8iDbiRZ8vNTu/E91KrE8mWJtcZeL4ZDkSnKmtIsgHIoIm0vuAE9zDSltKczlbfwm4yny/vtQ9MbndZ6I4pGYk1LVSRpHaIn6\
pEGDBR0bjCDuUbr8DZhxwJZaVQ8INgRADKy4odhZJcv2GvO0vn2vtOMDThV6aNSUow/IVcrJE+Qq5e6dJ7COJ/OjPWDTm/lJ2S3oX453cfRxlFEj6R8D3ZC9uxRwpjK0ZCShllXNJkfgnXb+Lym20FrMqQeczKJA\
xtq65KS2xvvhFk9aldCVZr5IKLDryxOZWJH6qL/OVDdSn9peliOV0zBWTg71+3Ji0yB1oiDLXSWUdPYAGX1lnkaRmbwDdjlbNGXnUonafIMWhkYRtWvCQ7fNJzRSvSZrtYxT1qepgg5ZmYTVSrIyrrGXtu1khxd2\
YtrMIjRBLLUllonT/D8coZZCzHvI4gFeTf8p7ZHi/m3JR+1F+Sj3V94z2hTFemh/YHXoI3YI5r5gbBT2qG7W12QpbKNAU4zEgeS5w7XSB9OpHES9IgcRTFdHWxWcMBMqlN6JzS6OjNOr9hj0GsHS+SWdhq1D/Lp4\
m7W4h7cm2LsxvwGIp72WxTFgpfyqdFhNXFmMuz2AIc/oJp+a0uImykGpELanvS4JZtxjszr5sPrUQs700HsEU97goGWkDUiVoPRXq0YaLzaOGyqfPf4spAkG8aAgoc5oMuMMF2EF88BMLS/LpD9ZEVbtz1zI1rHh\
M3oUktXwNh6LJtbq/oT7odc4+07sTmJVVQhqaFo17K4CZBgbeu+PtnA0iCv19DHLuQTwf9v2h8iuc7cQu0qX+7R1MVyuCyrdGSLLrM+3CNjG0VVXWDrOuMphmqTXZwc4zpbSSMS35JCREUxT7MjF0VwRVMYq2pft\
Okr1fKCVjlOpxzoIzXU81QLxRu/FUo9aCQ2HhjL9Ikcnn0V2QPxiRxDN8B6I+dRAgzkfMT/c5t0BMEqOodG1JALktQotYgnq5FDDcDqd8Z4jY+Oim4Wmfo8kUxFPoZOcXkZPiCEXkaTbDsfA8WuyxjoYvp9Rke9O\
0WmUcmZ4Ex0ZWFowTLpoGQ9PQ1m7R53NZyFj97vaTwIU2IKBYUUADz0manZlE9nSSh+roihC7lAQVRMOxraR2VS62hWJkMnQXQ1dOo7X1yR3K2oJWfDx5LvokSq5AUSWUJnIdsHkxP9Q/0BBhb7HTlnYYzZVStnS\
cAtiR8v5bOglCNDY8UfkPqjXSPPwSAOqOflHFymXXt4qdzNhbdVvbLTlVeeZEsomUjhevT39aAGLLAkdlLEUgXncqEMnPC1vvqYzbwvVq+h80Sk806fSNYgjBxj5vVOupp8w8qKrYiT0pOLBEg6EKhZxpFTjmdhG\
M54Fy0pic5lWJzejTeAOUgzi7Q/cSbN5f2kSl6qEM0TplmsqL+kq9wbtuydBNG7Kzt5IeKQsrrr8iDaihCN8SAA3TX49HB4Iv/C07s3yIB6NzBdG2ethd3vXJ4cIva6TVZbhaiDlJVZJUyfr7hGvmMgNdsIGLmKY\
ppu/jSgPpwNUd/XnIrQqNSLOZhF9Cetr91OMiz6evmnj6V4nPCwHVf/6X3iNK9j8LY/5xX+KcnqzHRsKiNBtR4YurV/ck/glKKWa88GrVEpJMfOqn6fsztwHptfvtSAr/oufUTdhI53Hiw4OEA9oWhOnmTJeL1Pd\
ixqIirtcRFO3hrwjQhf3poycKoeSfe1S7VNgc218P+U63Md4J8zlclGl9uSCo00jgeBZ2cuKBsGGnW13DzkSWclGa7cb0dAvc8rLEcioDxKrbDcwFBJUOKDBw6x8MMDfZrQ+l/FWVc1vi3CvZs07YOPnePemMjTN\
TfMsWFSHOmsu3OJXiprdVTRxuDSxMe+6c5qLNmvML3Iv1Egp2HCgqwaXC6dUH0854OmugYWLk0ICnySYlZt1CsU0ckdC9GKY8zqiwuJO6/Fk1dlP4faT5wAIJJ20rBZ0KcIXKLiu1HAXoo4lLI4Yat2B5Kl2LB5W\
SNTQYri26uOoZJBVupyZwwbJ7NZvhbISt9m1FJi2kH4bG24RpWEk92sk06yFfLqjimEIEcydc7oDtFtIt6uWxj+1LOT2PcQj8mvXmS+ZlqEqA37tOjrDar7hlHv8mm9vb7FY+vwQUmvhKUAW9Gn2O4NLtb8xks6g\
HKB0oLnWk654OChAXiU087V1x3YIzz1dC6GK/t7kczsiW5OLSs1SC8t1+CqnEGl2Yz3v/YB9uvemkGUUXUM+kq/RJzNGwqtyMXmWS5NQAVrAXDK539aCVKIh6KZvOXZebu0/S41r5esouvRJ3R8iH+rR2o4SLXdK\
nBoB3O07tOylWV70b0kLN3GvKQQdxWCOvxUiEz6PcGb0Tpp4ZWwkXkzn3sWXpPwhAZAHX45V0qajQeTIbiKayz+PZThdBcpP5NLSzRd1p0bMjiUzd93M/CqMV+r+V5Xn3tJnKZKEU3s0eSnAoCmunwr0iuOFlEDY\
kWtPargk0hoMjekL6Vn7ITJk1NYqWef7bFP/c7RjLf8D+x2HLaZLZtmhwkYbo9u+im2MBJJFmyFkrSQ4ujD+M6fKJrTDVtq/N4Qxw3LoqRRJ/lzmV8yNzR9QLZvzErQk6euylC0d7/Yk9ajoTtMKK+5HyajpYZ8e\
FmxpZIB0wZ24vU8Cq2ivkyxNsOVP4t4FZwKh9xVggW28YO5VckuuoVT7ldqJ8FupxPQ/BqLOp2xXu5HYs7knfe1q+JAJbTXnhoPZ9ce5VFL07Sf55l8MbggJ9OWbtOHadk62yvbkGxdDd1kc2oQBwp6MGWD8M4KD\
ptnir37s4OX6De7J23AlZ6VNm0n3FE5CBoj7Jyt1YJGN+XMPyj3haclYKmOiel8KwMB6pWU3im+aLQMRm7A2ZaWhKUharaVuJkWVUWlGlFbK4n4or8NlWM791taWK/s15FwszIOb0TUo1R2u8uXbwka51E6ok9im\
p9jY3dF8I1TQJxG88t+cuJANpNyCwZl93Ed18rR5Dpqf77zCTeqrjdc4/zWIeYPXe82PeP3jDjBouD9fdO6DCG/U5t01+qr5tz8W5Qm+bdbKDHSi0mTg39RHi5Mv7aAuTOoHq3JR0kfQ4QO3UEcMqLGPNK+u5d+/\
Ea783wNxerxEgScP/+kME00mXAbEOcg420lFKRt2J/ssZHnwY0uKXUHV3+2r0nT2oy8TjBDIM9a4q9bfRjp3LiwzhHBq9Klzq0FSrpeG/z//sSrl+N6ZqRDSoWlTFNfTczosBsXw/L/W0msp\
""")))
ESP32H2ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
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\
""")))
ESP32C2ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
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\
""")))
ESP32P4ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
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
