# Big thx to Michael Kandziora for this GUI port to PyQt5
import sys
import threading
import os
import platform
import distro

from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QPushButton, QLabel, QComboBox,
                             QFileDialog, QTextEdit, QGroupBox, QGridLayout,
                             QLineEdit)
from PyQt5.QtGui import QColor, QPalette
from PyQt5.QtCore import pyqtSignal, QObject

from esp_flasher.own_esptool import get_port_list
from esp_flasher.const import __version__
from esp_flasher.console_color import ColoredConsole

class FlashingThread(threading.Thread):
    finished = None  # Will be set to a Qt signal for success
    failed = None    # Will be set to a Qt signal for failure
    
    def __init__(self, firmware, port):
        threading.Thread.__init__(self)
        self.daemon = True
        self._firmware = firmware
        self._port = port

    def run(self):
        try:
            from esp_flasher.__main__ import run_esp_flasher

            argv = ['esp_flasher', '--port', self._port, self._firmware]
            
            # Call with skip_logs=True so it returns after flashing
            run_esp_flasher(argv, skip_logs=True)
            
            # Emit success signal
            if self.finished:
                self.finished.emit()
                
        except Exception as e:
            print(f"\033[31mFlashing error: {e}\033[0m")
            # Emit failure signal
            if self.failed:
                self.failed.emit()

class MainWindow(QMainWindow):
    flash_finished = pyqtSignal()
    flash_failed = pyqtSignal()
    
    def __init__(self):
        super().__init__()

        self._firmware = None
        self._port = None
        self._colored_console = None
        self._serial_reader = None
        self._serial_port = None
        self._was_connected_before_flash = False
        self._is_flashing = False

        self.init_ui()
        # Redirect stdout to colored console
        self._colored_console = ColoredConsole(self.console)
        sys.stdout = self._colored_console
        
        # Connect flash signals
        self.flash_finished.connect(self.on_flash_finished)
        self.flash_failed.connect(self.on_flash_failed)

    def init_ui(self):
        self.setWindowTitle(f"Tasmota-Esp-Flasher {__version__}")
        self.setGeometry(100, 100, 800, 600)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        vbox = QVBoxLayout()

        port_group_box = QGroupBox("Serial Port")
        port_layout = QGridLayout()
        port_label = QLabel("Select Port:")
        self.port_combobox = QComboBox()
        self.port_combobox.currentIndexChanged.connect(self.on_port_changed)
        
        # Connect button to establish connection (also reloads ports if needed)
        self.connect_button = QPushButton("Connect")
        self.connect_button.clicked.connect(self.toggle_connection)
        
        port_layout.addWidget(port_label, 0, 0)
        port_layout.addWidget(self.port_combobox, 0, 1)
        port_layout.addWidget(self.connect_button, 0, 2)
        port_group_box.setLayout(port_layout)

        firmware_group_box = QGroupBox("Firmware")
        firmware_layout = QGridLayout()
        firmware_label = QLabel("Select Firmware:")
        self.firmware_button = QPushButton("Browse")
        self.firmware_button.clicked.connect(self.pick_file)
        firmware_layout.addWidget(firmware_label, 0, 0)
        firmware_layout.addWidget(self.firmware_button, 0, 1)
        firmware_group_box.setLayout(firmware_layout)

        actions_group_box = QGroupBox("Actions")
        actions_layout = QHBoxLayout()
        self.flash_button = QPushButton("Flash ESP")
        self.flash_button.clicked.connect(self.flash_esp)
        actions_layout.addWidget(self.flash_button)
        actions_group_box.setLayout(actions_layout)

        # Console with input field
        console_group_box = QGroupBox("Console")
        console_layout = QVBoxLayout()
        
        # Console output
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        console_layout.addWidget(self.console)
        
        # Input area (always visible, but disabled when not connected)
        input_widget = QWidget()
        input_layout = QHBoxLayout()
        input_layout.setContentsMargins(0, 4, 0, 0)
        
        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("Type command and press Enter (connect to device first)...")
        self.input_field.returnPressed.connect(self.send_command)
        self.input_field.setEnabled(False)
        
        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_command)
        self.send_button.setEnabled(False)
        
        self.clear_button = QPushButton("Clear")
        self.clear_button.clicked.connect(self.clear_console)
        
        input_layout.addWidget(self.input_field)
        input_layout.addWidget(self.send_button)
        input_layout.addWidget(self.clear_button)
        
        input_widget.setLayout(input_layout)
        
        console_layout.addWidget(input_widget)
        console_group_box.setLayout(console_layout)

        vbox.addWidget(port_group_box)
        vbox.addWidget(firmware_group_box)
        vbox.addWidget(actions_group_box)
        vbox.addWidget(console_group_box)

        central_widget.setLayout(vbox)
        
        # Now that UI is complete, load ports and connect
        self.reload_ports()

    def reload_ports(self):
        """Load available serial ports into combobox"""
        current_port = self._port
        self.port_combobox.clear()
        ports = get_port_list()
        if ports:
            self.port_combobox.addItems(ports)
            # Try to select the previously selected port
            if current_port and current_port in ports:
                index = ports.index(current_port)
                self.port_combobox.setCurrentIndex(index)
            else:
                self._port = ports[0]
        else:
            self.port_combobox.addItem("No ports found")
            self._port = None  # Clear port when none found

    def on_port_changed(self, index):
        """Called when port selection changes in combobox"""
        # Only update port if not connected
        if not (self._serial_port and self._serial_port.is_open):
            self._port = self.port_combobox.itemText(index)
    
    def toggle_connection(self):
        """Toggle connection on/off when Connect button is clicked"""
        if self._is_flashing:
            self.show_log_error("Cannot change connection while flashing")
            return
            
        if self._serial_port and self._serial_port.is_open:
            # Currently connected, so disconnect
            self.disconnect_from_port()
        else:
            # Not connected, so connect
            # Always reload ports to ensure we have the latest list
            self.reload_ports()
            
            if self._port:
                self.connect_to_port()
            else:
                # No ports found - inform user that rescan was performed
                self._colored_console.write("\033[33mNo serial ports found. Please connect a device and click Connect again.\033[0m\n")
    
    def disconnect_from_port(self):
        """Disconnect from serial port"""
        if not self._serial_port or not self._serial_port.is_open:
            return
        
        # Stop the serial reader first
        self.stop_serial()
        
        # Re-enable port selection
        self.port_combobox.setEnabled(True)
        
        # Update button appearance
        self.connect_button.setText("Connect")
        self.connect_button.setStyleSheet("")  # Reset to default style
        
        print(f"\033[33mDisconnected from {self._port}\033[0m")
    
    def connect_to_port(self):
        """Connect to the selected serial port"""
        if not self._port:
            return
        
        # Stop any existing connection
        self.stop_serial()
        
        # Start serial communication
        try:
            import serial
            from esp_flasher.serial_console import SerialReader
            
            self._serial_port = serial.Serial(self._port, baudrate=115200, timeout=1)
            
            # Start reader thread
            self._serial_reader = SerialReader(self._serial_port)
            self._serial_reader.line_received.connect(self.append_log_line)
            self._serial_reader.error_occurred.connect(self.handle_serial_error)
            self._serial_reader.start()
            
            # Enable input controls
            self.input_field.setEnabled(True)
            self.send_button.setEnabled(True)
            self.input_field.setPlaceholderText("Type command and press Enter...")
            
            # Disable port selection while connected
            self.port_combobox.setEnabled(False)
            
            # Update button appearance - green background when connected
            self.connect_button.setText("Disconnect")
            self.connect_button.setStyleSheet("background-color: #2d5016; color: white;")
            
            self._colored_console.write(f"\033[32mConnected to {self._port} at 115200 baud\033[0m\n")
            
        except Exception as e:
            self.show_log_error(f"Failed to open serial port: {e}")
            self.stop_serial()
            self.connect_button.setText("Connect")
            self.connect_button.setStyleSheet("")
            self.port_combobox.setEnabled(True)

    def pick_file(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Select Firmware File", "", "Binary Files (*.bin);;All Files (*)", options=options)
        if file_name:
            self._firmware = file_name
            self.firmware_button.setText(file_name)

    def flash_esp(self):
        if self._is_flashing:
            self.show_log_error("Flashing already in progress")
            return
            
        if not self._firmware or not self._port:
            if not self._port:
                print("\033[31mNo serial port selected!\033[0m")
            if not self._firmware:
                print("\033[31mNo firmware file selected!\033[0m")
            return
        
        # Remember if we were connected
        self._was_connected_before_flash = self._serial_port and self._serial_port.is_open
        
        # IMPORTANT: Completely disconnect and wait for port to be released
        if self._was_connected_before_flash:
            print("\033[33mDisconnecting from serial port for flashing...\033[0m")
            self.disconnect_from_port()
            
            # Give the OS time to release the port
            from PyQt5.QtCore import QTimer
            # Wait 500ms then start flashing
            QTimer.singleShot(500, self._start_flash_worker)
        else:
            self._start_flash_worker()
    
    def _start_flash_worker(self):
        """Start the flashing worker thread"""
        self._colored_console.clear()
        
        # Set flashing flag and disable UI
        self._is_flashing = True
        self.flash_button.setEnabled(False)
        self.connect_button.setEnabled(False)
        self.port_combobox.setEnabled(False)
        
        # Create worker and connect its signals
        self._flash_worker = FlashingThread(self._firmware, self._port)
        self._flash_worker.finished = self.flash_finished
        self._flash_worker.failed = self.flash_failed
        self._flash_worker.start()
    
    def on_flash_finished(self):
        """Called when flashing is complete"""
        print("\033[32m\nFlashing complete!\033[0m")
        
        # Clear flashing flag and re-enable UI
        self._is_flashing = False
        self.flash_button.setEnabled(True)
        self.connect_button.setEnabled(True)
        if not (self._serial_port and self._serial_port.is_open):
            self.port_combobox.setEnabled(True)
        
        # Reconnect immediately if we were connected before
        if self._was_connected_before_flash:
            self._reconnect_after_flash()
    
    def on_flash_failed(self):
        """Called when flashing fails"""
        print("\033[31m\nFlashing failed!\033[0m")
        
        # Clear flashing flag and re-enable UI
        self._is_flashing = False
        self.flash_button.setEnabled(True)
        self.connect_button.setEnabled(True)
        if not (self._serial_port and self._serial_port.is_open):
            self.port_combobox.setEnabled(True)
    
    def _reconnect_after_flash(self):
        """Reconnect to serial port after flash"""
        try:
            self.connect_to_port()
        except Exception as e:
            print(f"\033[31mFailed to reconnect: {e}\033[0m")
    
    def stop_serial(self):
        """Stop serial communication"""
        # Stop reader thread first
        if self._serial_reader:
            self._serial_reader.stop()
            self._serial_reader = None
        
        # Close serial port and ensure it's fully released
        if self._serial_port:
            try:
                if self._serial_port.is_open:
                    self._serial_port.close()
                # Give OS time to release the port
                import time
                time.sleep(0.1)
            except Exception as e:
                print(f"Error closing serial port: {e}")
            finally:
                self._serial_port = None
        
        # Disable input controls (check if they exist first)
        if hasattr(self, 'input_field'):
            self.input_field.setEnabled(False)
        if hasattr(self, 'send_button'):
            self.send_button.setEnabled(False)
        if hasattr(self, 'input_field'):
            self.input_field.setPlaceholderText("Type command and press Enter (connect to device first)...")
    
    def send_command(self):
        """Send command to serial port"""
        if not self._serial_port or not self._serial_port.is_open:
            self.show_log_error("Serial port not open")
            return
        
        command = self.input_field.text()
        if not command:
            return
        
        try:
            # Send command with newline
            self._serial_port.write((command + "\r\n").encode())
            
            # Echo command to console
            self._colored_console.write(f"\033[36m> {command}\033[0m\n")
            
            # Clear input field
            self.input_field.clear()
            
        except Exception as e:
            self.handle_serial_error(f"Failed to send command: {e}")
    
    def append_log_line(self, line):
        """Append a line to the console"""
        # Preserve bare \r for progress indicators
        if line.endswith("\r"):
            self._colored_console.write(line)
        else:
            self._colored_console.write(line + "\n")
    
    def show_log_error(self, message):
        """Show error message in console"""
        self._colored_console.write(f"\033[31m{message}\033[0m\n")
    
    def handle_serial_error(self, message):
        """Handle serial errors by showing message and disconnecting"""
        self.show_log_error(message)
        self.stop_serial()
        self.port_combobox.setEnabled(True)
        self.connect_button.setText("Connect")
        self.connect_button.setStyleSheet("")
    
    def clear_console(self):
        """Clear the console"""
        self._colored_console.clear()
    
    def closeEvent(self, event):
        """Handle window close event"""
        if self._is_flashing:
            self.show_log_error("Cannot close window while flashing is in progress")
            event.ignore()
            return
            
        if self._serial_port and self._serial_port.is_open:
            self.disconnect_from_port()
        super().closeEvent(event)

def get_qt_platform_for_linux():
    """Detect the best Qt platform for Linux based on session type and available plugins."""
    # Check if we're in a Wayland session
    session_type = os.environ.get('XDG_SESSION_TYPE', '').lower()
    wayland_display = os.environ.get('WAYLAND_DISPLAY', '')
    
    # Prefer wayland if we're in a wayland session and wayland display is available
    if session_type == 'wayland' and wayland_display:
        return 'wayland'
    
    # Check if we're explicitly in an X11 session
    if session_type == 'x11' or os.environ.get('DISPLAY'):
        return 'xcb'
    
    # Fallback to wayland for unknown cases
    return 'wayland'

def set_qt_qpa_platform_if_not_set():
    """Set QT_QPA_PLATFORM based on session detection, but only if not already set."""
    if 'QT_QPA_PLATFORM' not in os.environ:
        os_name = platform.system()
        if os_name == 'Darwin':
            os.environ['QT_QPA_PLATFORM'] = 'cocoa'
        elif os_name == 'Linux':
            os.environ['QT_QPA_PLATFORM'] = get_qt_platform_for_linux()
        elif os_name == 'Windows':
            os.environ['QT_QPA_PLATFORM'] = 'windows'
        else:
            os.environ['QT_QPA_PLATFORM'] = 'offscreen'


def main():

    set_qt_qpa_platform_if_not_set()
    app = QApplication(sys.argv)

    app.setStyle("Fusion")
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(53, 53, 53))
    palette.setColor(QPalette.WindowText, QColor(255, 255, 255))
    palette.setColor(QPalette.Base, QColor(35, 35, 35))
    palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
    palette.setColor(QPalette.ToolTipBase, QColor(255, 255, 255))
    palette.setColor(QPalette.ToolTipText, QColor(255, 255, 255))
    palette.setColor(QPalette.Text, QColor(255, 255, 255))
    palette.setColor(QPalette.Button, QColor(53, 53, 53))
    palette.setColor(QPalette.ButtonText, QColor(255, 255, 255))
    palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
    palette.setColor(QPalette.Link, QColor(42, 130, 218))
    palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
    palette.setColor(QPalette.HighlightedText, QColor(0, 0, 0))
    app.setPalette(palette)

    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
