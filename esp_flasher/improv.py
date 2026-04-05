"""
Improv Wi-Fi Serial Protocol implementation for ESP-Flasher.
Based on the Improv Serial specification and esp32tool js/improv.js reference.
"""

import time
import threading
import logging

from PyQt6.QtCore import pyqtSignal, QObject

logger = logging.getLogger(__name__)

# Improv packet header
IMPROV_HEADER = b"IMPROV"
IMPROV_VERSION = 0x01

# Message types
TYPE_CURRENT_STATE = 0x01
TYPE_ERROR_STATE = 0x02
TYPE_RPC = 0x03
TYPE_RPC_RESULT = 0x04

# Device states
STATE_READY = 0x02
STATE_PROVISIONING = 0x03
STATE_PROVISIONED = 0x04

STATE_NAMES = {
    STATE_READY: "Ready",
    STATE_PROVISIONING: "Provisioning",
    STATE_PROVISIONED: "Provisioned",
}

# Error codes
ERROR_NONE = 0x00
ERROR_INVALID_RPC = 0x01
ERROR_UNKNOWN_RPC = 0x02
ERROR_UNABLE_TO_CONNECT = 0x03
ERROR_TIMEOUT = 0xFE
ERROR_UNKNOWN = 0xFF

ERROR_NAMES = {
    ERROR_NONE: "No error",
    ERROR_INVALID_RPC: "Invalid RPC packet",
    ERROR_UNKNOWN_RPC: "Unknown RPC command",
    ERROR_UNABLE_TO_CONNECT: "Unable to connect",
    ERROR_TIMEOUT: "Timeout",
    ERROR_UNKNOWN: "Unknown error",
}

# RPC commands
CMD_SEND_WIFI_SETTINGS = 0x01
CMD_REQUEST_CURRENT_STATE = 0x02
CMD_REQUEST_INFO = 0x03
CMD_REQUEST_WIFI_NETWORKS = 0x04

# Timeouts (match esp32tool js/improv.js)
PROVISION_TIMEOUT = 30.0


def _build_packet(msg_type, data):
    """Build an Improv serial packet."""
    payload = bytearray(IMPROV_HEADER)
    payload.append(IMPROV_VERSION)
    payload.append(msg_type)
    payload.append(len(data))
    payload.extend(data)
    checksum = sum(payload) & 0xFF
    payload.append(checksum)
    payload.append(0x0A)
    return bytes(payload)


def _build_rpc(command, payload=b""):
    """Build an RPC packet with the given command and payload."""
    data = bytearray()
    data.append(command)
    data.append(len(payload))
    data.extend(payload)
    return _build_packet(TYPE_RPC, data)


def _build_wifi_payload(ssid, password):
    """Build the WiFi settings payload (TLV encoded SSID + password)."""
    ssid_bytes = ssid.encode("utf-8")
    pw_bytes = password.encode("utf-8")
    payload = bytearray()
    payload.append(len(ssid_bytes))
    payload.extend(ssid_bytes)
    payload.append(len(pw_bytes))
    payload.extend(pw_bytes)
    return bytes(payload)


def _parse_tlv_strings(data):
    """Parse TLV-encoded strings from RPC result data."""
    if len(data) < 2:
        return []
    total_length = data[1]
    strings = []
    idx = 2
    while idx < 2 + total_length and idx < len(data):
        str_len = data[idx]
        idx += 1
        if idx + str_len > len(data):
            break
        s = data[idx:idx + str_len].decode("utf-8", errors="replace")
        strings.append(s)
        idx += str_len
    return strings


class ImprovManager(QObject):
    """Manages Improv serial communication with an ESP device.

    Receiver state machine mirrors the JS reference (esp32tool js/improv.js):
      - is_improv=None   (scanning: accumulate bytes, check at 9 bytes)
      - is_improv=True   (reading improv packet body + checksum)
      - is_improv=False  (skip non-improv line until newline)
    """

    # Signals
    state_changed = pyqtSignal(int)          # device state
    error_received = pyqtSignal(int)         # error code
    device_info_received = pyqtSignal(list)  # [firmware, version, chip, name]
    wifi_networks_received = pyqtSignal(list)  # list of (ssid, rssi, secured)
    provisioned = pyqtSignal(list)           # result strings (e.g. redirect URL)
    log_message = pyqtSignal(str)            # log/status messages

    def __init__(self, serial_port):
        super().__init__()
        self._port = serial_port
        self._running = False
        self._thread = None

        # Receiver state machine (matches JS: undefined/true/false)
        self._line = []
        self._is_improv = None  # None=scanning, True=reading packet, False=skip line
        self._improv_length = 0

        # RPC response synchronization
        self._rpc_event = threading.Event()
        self._rpc_result = None
        self._rpc_error = None
        self._rpc_command = None

        # WiFi network scan accumulator
        self._wifi_networks = []
        self._wifi_scan_done = threading.Event()

        # Current device state
        self.device_state = None

    def start(self):
        """Start the Improv receiver thread."""
        self._running = True
        self._thread = threading.Thread(target=self._read_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop the Improv receiver thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None

    # --- Public API ---

    def request_current_state(self):
        """Request the current state from the device."""
        pkt = _build_rpc(CMD_REQUEST_CURRENT_STATE)
        self._write(pkt)

    def request_device_info(self):
        """Request device info. Returns [firmware, version, chip, name] or None.
        No timeout — matches JS where requestInfo() waits indefinitely."""
        return self._send_rpc(CMD_REQUEST_INFO)

    def request_wifi_networks(self):
        """Scan for WiFi networks. Returns list of (ssid, rssi, secured).
        No timeout — matches JS where scan() waits indefinitely."""
        self._wifi_networks = []
        self._wifi_scan_done.clear()
        pkt = _build_rpc(CMD_REQUEST_WIFI_NETWORKS)
        self._write(pkt)
        self._wifi_scan_done.wait()
        return list(self._wifi_networks)

    def send_wifi_settings(self, ssid, password, timeout=PROVISION_TIMEOUT):
        """Send WiFi credentials. Returns result strings or None on error.
        30s timeout — matches JS provision(ssid, password, 30000)."""
        payload = _build_wifi_payload(ssid, password)
        return self._send_rpc(CMD_SEND_WIFI_SETTINGS, payload, timeout=timeout)

    # --- Internal ---

    def _send_rpc(self, command, payload=b"", timeout=None):
        """Send an RPC command and wait for the result.
        timeout=None means wait indefinitely (matches JS behavior for info/scan)."""
        self._rpc_event.clear()
        self._rpc_result = None
        self._rpc_error = None
        self._rpc_command = command

        pkt = _build_rpc(command, payload)
        self._write(pkt)

        if self._rpc_event.wait(timeout=timeout):
            if self._rpc_error is not None and self._rpc_error != ERROR_NONE:
                return None
            return self._rpc_result
        self.log_message.emit("RPC timeout")
        self.error_received.emit(ERROR_TIMEOUT)
        return None

    def _write(self, data):
        """Write data to the serial port."""
        try:
            if self._port and self._port.is_open:
                self._port.write(data)
                self._port.flush()
        except Exception as e:
            logger.error("Improv write error: %s", e)
            self.log_message.emit(f"Write error: {e}")

    def _read_loop(self):
        """Background thread: read bytes and detect Improv packets."""
        while self._running:
            try:
                if not self._port or not self._port.is_open:
                    break
                if self._port.in_waiting > 0:
                    raw = self._port.read(self._port.in_waiting)
                    for b in raw:
                        self._process_byte(b)
                else:
                    time.sleep(0.01)
            except Exception as e:
                if self._running:
                    logger.error("Improv read error: %s", e)
                break

    def _process_byte(self, byte):
        """Process a single byte — exact port of JS _processInput state machine."""

        # State: is_improv=False → skip non-improv line until newline
        if self._is_improv is False:
            if byte == 0x0A:
                self._is_improv = None
            return

        # State: is_improv=True → collecting improv packet body
        if self._is_improv is True:
            self._line.append(byte)
            if len(self._line) == self._improv_length:
                self._handle_packet(self._line)
                self._is_improv = None
                self._line = []
            return

        # State: is_improv=None → scanning for header

        # Newline resets accumulation
        if byte == 0x0A:
            self._line = []
            return

        self._line.append(byte)

        # Only check once we have exactly 9 bytes
        if len(self._line) != 9:
            return

        # Check if first 6 bytes match "IMPROV"
        if bytes(self._line[:6]) == IMPROV_HEADER:
            # Header matched — calculate total packet length
            data_len = self._line[8]
            self._improv_length = 9 + data_len + 1  # 9 header + data + checksum
            self._is_improv = True
        else:
            # Not an Improv header — discard and go back to scanning
            # (JS does: isImprov = false, line = [])
            self._line = []
            self._is_improv = None

    def _handle_packet(self, line):
        """Handle a complete Improv packet (including header + checksum)."""
        # Checksum: sum of all bytes except the last one (the checksum itself)
        calculated = sum(line[:-1]) & 0xFF
        received = line[-1]
        if calculated != received:
            logger.warning("Improv checksum mismatch: expected %02X, got %02X",
                           calculated, received)
            return

        # Parse fields after the 6-byte "IMPROV" prefix
        version = line[6]
        if version != IMPROV_VERSION:
            return

        msg_type = line[7]
        data_len = line[8]
        data = line[9:9 + data_len]

        if msg_type == TYPE_CURRENT_STATE:
            if data:
                self.device_state = data[0]
                state_name = STATE_NAMES.get(data[0], f"Unknown ({data[0]:#x})")
                self.log_message.emit(f"Device state: {state_name}")
                self.state_changed.emit(data[0])

        elif msg_type == TYPE_ERROR_STATE:
            if data:
                error = data[0]
                error_name = ERROR_NAMES.get(error, f"Unknown ({error:#x})")
                if error != ERROR_NONE:
                    self.log_message.emit(f"Device error: {error_name}")
                self.error_received.emit(error)
                if error != ERROR_NONE:
                    self._rpc_error = error
                    self._rpc_event.set()

        elif msg_type == TYPE_RPC_RESULT:
            if not data:
                return
            command = data[0]
            strings = _parse_tlv_strings(data)

            if command == CMD_REQUEST_INFO:
                self.log_message.emit(f"Device info: {strings}")
                self.device_info_received.emit(strings)
                self._rpc_result = strings
                self._rpc_event.set()

            elif command == CMD_REQUEST_WIFI_NETWORKS:
                if not strings:
                    self._wifi_scan_done.set()
                else:
                    if len(strings) >= 3:
                        self._wifi_networks.append(
                            (strings[0], int(strings[1]), strings[2] == "YES")
                        )

            elif command == CMD_SEND_WIFI_SETTINGS:
                self.log_message.emit(f"Provisioned: {strings}")
                self.provisioned.emit(strings)
                self._rpc_result = strings
                self._rpc_event.set()

            else:
                self._rpc_result = strings
                self._rpc_event.set()
