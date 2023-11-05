#!/usr/bin/env python
#
# SPDX-FileCopyrightText: 2014-2022 Fredrik Ahlberg, Angus Gratton, Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import division, print_function

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


__version__ = "3.4.0"

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

SUPPORTED_CHIPS = ['esp8266', 'esp32', 'esp32s2', 'esp32s3', 'esp32c3', 'esp32c6', 'esp32h2', 'esp32c2']


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
        'esp32c3': ESP32C3ROM,
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
        try:
            print('Detecting chip type...', end='')
            res = detect_port.check_command('get security info', ESPLoader.ESP_GET_SECURITY_INFO, b'')
            res = struct.unpack("<IBBBBBBBBI", res[:16])  # 4b flags, 1b flash_crypt_cnt, 7*1b key_purposes, 4b chip_id
            chip_id = res[9]  # 2/4 status bytes invariant

            for cls in [ESP32S3ROM, ESP32C3ROM, ESP32C6ROM, ESP32H2ROM, ESP32C2ROM]:
                if chip_id == cls.IMAGE_CHIP_ID:
                    inst = cls(detect_port._port, baud, trace_enabled=trace_enabled)
                    inst._post_connect()
                    try:
                        inst.read_reg(ESPLoader.CHIP_DETECT_MAGIC_REG_ADDR)  # Dummy read to check Secure Download mode
                    except UnsupportedCommandError:
                        inst.secure_download_mode = True
        except (UnsupportedCommandError, struct.error, FatalError) as e:
            # UnsupportedCmdErr: ESP8266/ESP32 ROM | struct.err: ESP32-S2 | FatalErr: ESP8266/ESP32 STUB
            print(" Unsupported detection protocol, switching and trying again...")
            try:
                # ESP32/ESP8266 are reset after an unsupported command, need to connect again (not needed on ESP32-S2)
                if not isinstance(e, struct.error):
                    detect_port.connect(connect_mode, connect_attempts, detecting=True, warnings=False)
                print('Detecting chip type...', end='')
                sys.stdout.flush()
                chip_magic_value = detect_port.read_reg(ESPLoader.CHIP_DETECT_MAGIC_REG_ADDR)

                for cls in [ESP8266ROM, ESP32ROM, ESP32S2ROM, ESP32S3ROM,
                            ESP32C3ROM, ESP32C6ROM, ESP32C2ROM, ESP32H2ROM]:
                    if chip_magic_value in cls.CHIP_DETECT_MAGIC_VALUE:
                        inst = cls(detect_port._port, baud, trace_enabled=trace_enabled)
                        inst._post_connect()
                        inst.check_chip_id()
            except UnsupportedCommandError:
                raise FatalError("Unsupported Command Error received. Probably this means Secure Download Mode is enabled, "
                                 "autodetection will not work. Need to manually specify the chip.")
        finally:
            if inst is not None:
                print(' %s' % inst.CHIP_NAME, end='')
                if detect_port.sync_stub_detected:
                    inst = inst.STUB_CLASS(inst)
                    inst.sync_stub_detected = True
                print('')  # end line
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
                    for cls in [ESP8266ROM, ESP32ROM, ESP32S2ROM, ESP32S3ROM,
                                ESP32C3ROM, ESP32H2ROM, ESP32C2ROM, ESP32C6ROM]:
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
        if isinstance(self, (ESP32S2ROM, ESP32S3ROM, ESP32C3ROM,
                             ESP32C6ROM, ESP32H2ROM, ESP32C2ROM)) and not self.IS_STUB:
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
        if isinstance(self, (ESP32S2ROM, ESP32C3ROM, ESP32S3ROM, ESP32H2ROM, ESP32C2ROM)) and not self.IS_STUB:
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
        if isinstance(self, (ESP32S2ROM, ESP32S3ROM, ESP32C3ROM,
                             ESP32C6ROM, ESP32H2ROM, ESP32C2ROM)) and not self.IS_STUB:
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
    GPIO_STRAP_SPI_BOOT_MASK = 0x8  # Not download mode
    RTC_CNTL_OPTION1_REG = 0x3F408128
    RTC_CNTL_FORCE_DOWNLOAD_BOOT_MASK = 0x1  # Is download mode forced over USB?

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

    def _check_if_can_reset(self):
        """
        Check the strapping register to see if we can reset out of download mode.
        """
        if os.getenv("ESPTOOL_TESTING") is not None:
            print("ESPTOOL_TESTING is set, ignoring strapping mode check")
            # Esptool tests over USB-OTG run with GPIO0 strapped low,
            # don't complain in this case.
            return
        strap_reg = self.read_reg(self.GPIO_STRAP_REG)
        force_dl_reg = self.read_reg(self.RTC_CNTL_OPTION1_REG)
        if (
            strap_reg & self.GPIO_STRAP_SPI_BOOT_MASK == 0
            and force_dl_reg & self.RTC_CNTL_FORCE_DOWNLOAD_BOOT_MASK == 0
        ):
            print(
                "WARNING: {} chip was placed into download mode using GPIO0.\n"
                "esptool.py can not exit the download mode over USB. "
                "To run the app, reset the chip manually.\n"
                "To suppress this note, set --after option to 'no_reset'.".format(
                    self.get_chip_description()
                )
            )
            raise SystemExit(1)

    def hard_reset(self):
        if self.uses_usb():
            self._check_if_can_reset()

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

    BOOTLOADER_FLASH_OFFSET = 0x0

    FPGA_SLOW_BOOT = False

    IROM_MAP_START = 0x42000000
    IROM_MAP_END   = 0x44000000
    DROM_MAP_START = 0x3c000000
    DROM_MAP_END   = 0x3e000000

    UART_DATE_REG_ADDR = 0x60000080

    SPI_REG_BASE = 0x60002000
    SPI_USR_OFFS    = 0x18
    SPI_USR1_OFFS   = 0x1c
    SPI_USR2_OFFS   = 0x20
    SPI_MOSI_DLEN_OFFS = 0x24
    SPI_MISO_DLEN_OFFS = 0x28
    SPI_W0_OFFS = 0x58

    FLASH_ENCRYPTED_WRITE_ALIGN = 16

    # todo: use espefuse APIs to get this info
    EFUSE_BASE = 0x60007000  # BLOCK0 read base address
    MAC_EFUSE_REG = EFUSE_BASE + 0x044
    EFUSE_BLOCK1_ADDR = EFUSE_BASE + 0x44
    EFUSE_BLOCK2_ADDR = EFUSE_BASE + 0x5C
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

    PURPOSE_VAL_XTS_AES256_KEY_1 = 2
    PURPOSE_VAL_XTS_AES256_KEY_2 = 3
    PURPOSE_VAL_XTS_AES128_KEY = 4

    UARTDEV_BUF_NO = 0x3fcef14c  # Variable in ROM .bss which indicates the port in use
    UARTDEV_BUF_NO_USB = 3  # Value of the above variable indicating that USB is in use

    USB_RAM_BLOCK = 0x800  # Max block size USB CDC is used

    GPIO_STRAP_REG = 0x60004038
    GPIO_STRAP_SPI_BOOT_MASK = 0x8   # Not download mode
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

    def _post_connect(self):
        if self.uses_usb():
            self.ESP_RAM_BLOCK = self.USB_RAM_BLOCK

    def _check_if_can_reset(self):
        """
        Check the strapping register to see if we can reset out of download mode.
        """
        if os.getenv("ESPTOOL_TESTING") is not None:
            print("ESPTOOL_TESTING is set, ignoring strapping mode check")
            # Esptool tests over USB CDC run with GPIO0 strapped low, don't complain in this case.
            return
        strap_reg = self.read_reg(self.GPIO_STRAP_REG)
        force_dl_reg = self.read_reg(self.RTC_CNTL_OPTION1_REG)
        if strap_reg & self.GPIO_STRAP_SPI_BOOT_MASK == 0 and force_dl_reg & self.RTC_CNTL_FORCE_DOWNLOAD_BOOT_MASK == 0:
            print("WARNING: {} chip was placed into download mode using GPIO0.\n"
                  "esptool.py can not exit the download mode over USB. "
                  "To run the app, reset the chip manually.\n"
                  "To suppress this note, set --after option to 'no_reset'.".format(self.get_chip_description()))
            raise SystemExit(1)

    def hard_reset(self):
        if self.uses_usb():
            self._check_if_can_reset()

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
    IROM_MAP_END   = 0x42800000
    DROM_MAP_START = 0x3c000000
    DROM_MAP_END   = 0x3c800000

    SPI_REG_BASE = 0x60002000
    SPI_USR_OFFS    = 0x18
    SPI_USR1_OFFS   = 0x1C
    SPI_USR2_OFFS   = 0x20
    SPI_MOSI_DLEN_OFFS = 0x24
    SPI_MISO_DLEN_OFFS = 0x28
    SPI_W0_OFFS = 0x58

    BOOTLOADER_FLASH_OFFSET = 0x0

    # Magic value for ESP32C3 eco 1+2 and ESP32C3 eco3 respectivly
    CHIP_DETECT_MAGIC_VALUE = [0x6921506f, 0x1b31506f]

    UART_DATE_REG_ADDR = 0x60000000 + 0x7c

    EFUSE_BASE = 0x60008800
    EFUSE_BLOCK1_ADDR = EFUSE_BASE + 0x044
    MAC_EFUSE_REG  = EFUSE_BASE + 0x044

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

    PURPOSE_VAL_XTS_AES128_KEY = 4

    GPIO_STRAP_REG = 0x3f404038

    FLASH_ENCRYPTED_WRITE_ALIGN = 16

    MEMORY_MAP = [[0x00000000, 0x00010000, "PADDING"],
                  [0x3C000000, 0x3C800000, "DROM"],
                  [0x3FC80000, 0x3FCE0000, "DRAM"],
                  [0x3FC88000, 0x3FD00000, "BYTE_ACCESSIBLE"],
                  [0x3FF00000, 0x3FF20000, "DROM_MASK"],
                  [0x40000000, 0x40060000, "IROM_MASK"],
                  [0x42000000, 0x42800000, "IROM"],
                  [0x4037C000, 0x403E0000, "IRAM"],
                  [0x50000000, 0x50002000, "RTC_IRAM"],
                  [0x50000000, 0x50002000, "RTC_DRAM"],
                  [0x600FE000, 0x60100000, "MEM_INTERNAL2"]]

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

    def get_chip_description(self):
        chip_name = {
            0: "ESP32-C3",
        }.get(self.get_pkg_version(), "unknown ESP32-C3")
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        return "%s (revision v%d.%d)" % (chip_name, major_rev, minor_rev)

    def get_chip_features(self):
        return ["Wi-Fi"]

    def get_crystal_freq(self):
        # ESP32C3 XTAL is fixed to 40MHz
        return 40

    def override_vddsdio(self, new_voltage):
        raise NotImplementedInROMError("VDD_SDIO overrides are not supported for ESP32-C3")

    def read_mac(self):
        mac0 = self.read_reg(self.MAC_EFUSE_REG)
        mac1 = self.read_reg(self.MAC_EFUSE_REG + 4)  # only bottom 16 bits are MAC
        bitstring = struct.pack(">II", mac1, mac0)[2:]
        try:
            return tuple(ord(b) for b in bitstring)
        except TypeError:  # Python 3, bitstring elements are already bytes
            return tuple(bitstring)

    def get_flash_crypt_config(self):
        return None  # doesn't exist on ESP32-C3

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
        # Need to see an AES-128 key
        purposes = [self.get_key_block_purpose(b) for b in range(6)]

        return any(p == self.PURPOSE_VAL_XTS_AES128_KEY for p in purposes)


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
        return ["BLE", "IEEE802.15.4"]

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

    # Magic value for ESP32C2 ECO0 and ECO1 respectively
    CHIP_DETECT_MAGIC_VALUE = [0x6F51306F, 0x7C41A06F]

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
        elif chip == 'esp32c6':
            return ESP32C6FirmwareImage(f)
        elif chip == 'esp32h2':
            return ESP32H2FirmwareImage(f)
        elif chip == 'esp32c2':
            return ESP32C2FirmwareImage(f)
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
        raise FatalError("Listing all serial ports is currently not available. Please try to specify the port when "
                         "running esptool.py or update the pyserial package to the latest version")
    return sorted(ports.device for ports in list_ports.comports())


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
ESP32C6ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
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\
OdSODoxyMzCDxb8B397NZQ==\
""")))
ESP32H2ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
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\
XMbtthxqTwfGKsnTbPVvMfzUqA==\
""")))
ESP32C2ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
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
