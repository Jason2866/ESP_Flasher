"""
Serial Console with input support for ESP-Flasher
Allows viewing logs and sending commands to the ESP device
"""

import threading
import serial
import logging
from datetime import datetime
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton, QTextEdit
from PyQt5.QtCore import pyqtSignal, QObject, Qt
from PyQt5.QtGui import QFont

from esp_flasher.console_color import ColoredConsole

# Set up logger for this module
logger = logging.getLogger(__name__)


class SerialReader(QObject):
    """Thread-safe serial port reader"""
    line_received = pyqtSignal(str)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, serial_port):
        super().__init__()
        self.serial_port = serial_port
        self.running = False
        self.thread = None
        # Use incremental decoder for proper UTF-8 handling
        import codecs
        self.decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')
    
    def start(self):
        """Start reading from serial port"""
        self.running = True
        self.thread = threading.Thread(target=self._read_loop, daemon=True)
        self.thread.start()
    
    def stop(self):
        """Stop reading from serial port"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)
    
    def _read_loop(self):
        """Read loop running in background thread"""
        buffer = ""
        while self.running:
            try:
                if self.serial_port and self.serial_port.is_open:
                    # Read available data
                    if self.serial_port.in_waiting > 0:
                        raw = self.serial_port.read(self.serial_port.in_waiting)
                        if raw:
                            # Use incremental decoder to handle multi-byte UTF-8 characters
                            text = self.decoder.decode(raw, False)
                            buffer += text
                            
                            # Process complete lines (ending with \n or \r)
                            while '\n' in buffer or '\r' in buffer:
                                # Find the first line ending
                                idx_n = buffer.find('\n')
                                idx_r = buffer.find('\r')
                                
                                # Determine which comes first
                                if idx_n == -1:
                                    idx = idx_r
                                    line_ending = '\r'
                                elif idx_r == -1:
                                    idx = idx_n
                                    line_ending = '\n'
                                else:
                                    if idx_n < idx_r:
                                        idx = idx_n
                                        line_ending = '\n'
                                    else:
                                        idx = idx_r
                                        line_ending = '\r'
                                
                                # Extract the line
                                line = buffer[:idx]
                                buffer = buffer[idx + 1:]
                                
                                # Skip \n if it follows \r (handle \r\n)
                                if line_ending == '\r' and buffer.startswith('\n'):
                                    buffer = buffer[1:]
                                    line_ending = '\n'
                                
                                # Emit the line if not empty
                                if line.strip():
                                    if line_ending == '\r':
                                        self._emit_line(line + '\r')
                                    else:
                                        self._emit_line(line)
                    else:
                        # No data available, small sleep to avoid busy loop
                        import time
                        time.sleep(0.01)
                else:
                    break
            except serial.SerialException as e:
                self.error_occurred.emit(f"Serial port error: {e}")
                break
            except Exception as e:
                self.error_occurred.emit(f"Unexpected error: {e}")
                break
    
    def _emit_line(self, line):
        """Emit a line with optional timestamp"""
        # Add timestamp only to lines that don't already have one
        # Check if line starts with a timestamp pattern (HH:MM:SS)
        has_timestamp = False
        if len(line) >= 8:
            # Check for patterns like "21:29:01" or "[21:29:01]"
            start_idx = 1 if line.startswith('[') else 0
            if (len(line) > start_idx + 7 and 
                line[start_idx + 2] == ':' and 
                line[start_idx + 5] == ':'):
                has_timestamp = True
        
        if not has_timestamp:
            time_ = datetime.now().time().strftime("[%H:%M:%S]")
            message = f"{time_} {line}"
        else:
            message = line
        
        self.line_received.emit(message)


class SerialConsoleWidget(QWidget):
    """
    A console widget for serial communication with input support.
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.serial_port = None
        self.serial_reader = None
        self.colored_console = None
        
        self.init_ui()
    
    def init_ui(self):
        """Initialize the UI components"""
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Console output area
        self.console_output = QTextEdit()
        self.console_output.setReadOnly(True)
        self.console_output.setFont(QFont("Courier", 10))
        
        # Initialize colored console
        self.colored_console = ColoredConsole(self.console_output)
        
        # Input area
        input_layout = QHBoxLayout()
        input_layout.setContentsMargins(8, 8, 8, 8)
        
        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("Type command and press Enter...")
        self.input_field.setFont(QFont("Courier", 10))
        self.input_field.returnPressed.connect(self.send_command)
        self.input_field.setEnabled(False)  # Disabled until serial port is opened
        
        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_command)
        self.send_button.setEnabled(False)  # Disabled until serial port is opened
        
        self.clear_button = QPushButton("Clear")
        self.clear_button.clicked.connect(self.clear_console)
        
        input_layout.addWidget(self.input_field)
        input_layout.addWidget(self.send_button)
        input_layout.addWidget(self.clear_button)
        
        # Add to main layout
        layout.addWidget(self.console_output)
        layout.addLayout(input_layout)
        
        self.setLayout(layout)
    
    def start_serial(self, port_name, baudrate=115200):
        """Start serial communication"""
        try:
            # Close existing connection if any
            self.stop_serial()
            
            # Open new serial port
            self.serial_port = serial.Serial(port_name, baudrate=baudrate, timeout=1)
            
            try:
                # Start reader thread
                self.serial_reader = SerialReader(self.serial_port)
                self.serial_reader.line_received.connect(self.append_line)
                self.serial_reader.error_occurred.connect(self.handle_serial_error)
                self.serial_reader.start()
                
                # Enable input
                self.input_field.setEnabled(True)
                self.send_button.setEnabled(True)
                self.input_field.setFocus()
                
                self.colored_console.write(f"\033[32mConnected to {port_name} at {baudrate} baud\033[0m\n")
                
            except Exception as e:
                # Clean up on failure
                if self.serial_reader:
                    self.serial_reader.stop()
                    self.serial_reader = None
                if self.serial_port:
                    self.serial_port.close()
                    self.serial_port = None
                raise
            
        except serial.SerialException as e:
            self.show_error(f"Failed to open serial port: {e}")
        except Exception as e:
            self.show_error(f"Unexpected error: {e}")
    
    def stop_serial(self):
        """Stop serial communication"""
        # Stop reader thread
        if self.serial_reader:
            self.serial_reader.stop()
            self.serial_reader = None
        
        # Close serial port
        if self.serial_port and self.serial_port.is_open:
            try:
                self.serial_port.close()
            except Exception as e:
                logger.debug("Error closing serial port: %s", e, exc_info=True)
            finally:
                self.serial_port = None
        
        # Disable input
        self.input_field.setEnabled(False)
        self.send_button.setEnabled(False)
    
    def send_command(self):
        """Send command to serial port"""
        if not self.serial_port or not self.serial_port.is_open:
            self.show_error("Serial port not open")
            return
        
        command = self.input_field.text()
        if not command:
            return
        
        try:
            # Send command with newline
            self.serial_port.write((command + "\r\n").encode())
            
            # Echo command to console
            self.colored_console.write(f"\033[36m> {command}\033[0m\n")
            
            # Clear input field
            self.input_field.clear()
            
        except serial.SerialException as e:
            self.handle_serial_error(f"Failed to send command: {e}")
        except Exception as e:
            self.handle_serial_error(f"Unexpected error: {e}")
    
    def append_line(self, line):
        """Append a line to the console"""
        # Preserve bare \r for progress indicators
        if line.endswith("\r"):
            self.colored_console.write(line)
        else:
            self.colored_console.write(line + "\n")
    
    def show_error(self, message):
        """Show error message in console"""
        self.colored_console.write(f"\033[31m{message}\033[0m\n")
    
    def handle_serial_error(self, message):
        """Handle serial errors by showing message and disconnecting"""
        self.show_error(message)
        self.stop_serial()
    
    def clear_console(self):
        """Clear the console output"""
        self.colored_console.clear()
    
    def closeEvent(self, event):
        """Handle widget close event"""
        self.stop_serial()
        super().closeEvent(event)
