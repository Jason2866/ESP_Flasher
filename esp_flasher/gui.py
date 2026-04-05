# Big thx to Michael Kandziora for this GUI port to PyQt5
import sys
import threading
import os
import platform

from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QPushButton, QLabel, QComboBox,
                             QFileDialog, QTextEdit, QGroupBox, QGridLayout,
                             QLineEdit, QDialog, QListWidget, QListWidgetItem,
                             QProgressBar, QMessageBox)
from PyQt6.QtGui import QColor, QPalette
from PyQt6.QtCore import pyqtSignal, QObject, Qt, QSettings, QTimer

from esp_flasher.own_esptool import get_port_list, colorize, COLOR_RED, COLOR_GREEN, COLOR_CYAN, COLOR_YELLOW
from esp_flasher.const import (__version__, DEFAULT_WINDOW_WIDTH, 
                               DEFAULT_WINDOW_HEIGHT, DEFAULT_WINDOW_X, 
                               DEFAULT_WINDOW_Y)
from esp_flasher.console_color import ColoredConsole


class DeviceInfoDialog(QDialog):
    """Attractive dialog to display device information."""
    
    def __init__(self, device_info, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Device Information")
        self.setMinimumWidth(400)
        self.setMinimumHeight(250)
        self._device_info = device_info
        self._init_ui()
    
    def _init_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Title
        title = QLabel("📱 Device Information")
        title.setStyleSheet("""
            QLabel {
                font-size: 18px;
                font-weight: bold;
                color: #2196F3;
                padding: 10px;
            }
        """)
        layout.addWidget(title)
        
        # Info card container
        card = QWidget()
        card.setStyleSheet("""
            QWidget {
                background-color: #f5f5f5;
                border-radius: 8px;
                padding: 15px;
            }
        """)
        card_layout = QVBoxLayout()
        card_layout.setSpacing(12)
        
        labels = ["Firmware", "Version", "Chip", "Name"]
        icons = ["⚙️", "🔢", "🔌", "📛"]
        
        for i, val in enumerate(self._device_info):
            if val and i < len(labels):
                info_row = QLabel(f"{icons[i]} <b>{labels[i]}:</b> {val}")
                info_row.setStyleSheet("""
                    QLabel {
                        font-size: 13px;
                        padding: 8px;
                        background-color: white;
                        color: #333333;
                        border-radius: 4px;
                        border-left: 3px solid #2196F3;
                    }
                """)
                info_row.setWordWrap(True)
                info_row.setTextFormat(Qt.TextFormat.RichText)
                card_layout.addWidget(info_row)
        
        card.setLayout(card_layout)
        layout.addWidget(card)
        
        layout.addStretch()
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 10px 20px;
                font-size: 13px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QPushButton:pressed {
                background-color: #0D47A1;
            }
        """)
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)
        
        self.setLayout(layout)


class ImprovDialog(QDialog):
    """Dialog for Improv WiFi provisioning."""
    _scan_finished = pyqtSignal(list)  # thread-safe signal for scan results
    _provision_failed_signal = pyqtSignal()  # thread-safe signal for provision failure

    def __init__(self, serial_port, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Improv WiFi Provisioning")
        self.setMinimumWidth(420)
        self._serial_port = serial_port  # reuse already-open port (never close it)
        self._improv = None
        self._is_provisioning = False  # True only after we send credentials
        self._scan_finished.connect(self._update_network_list)
        self._provision_failed_signal.connect(self._provision_failed)
        self._init_ui()
        self._start_improv()

    def _init_ui(self):
        layout = QVBoxLayout()

        # Device info - now with a button to show details
        info_container = QHBoxLayout()
        self.info_label = QLabel("Detecting Improv device...")
        self.info_label.setWordWrap(True)
        info_container.addWidget(self.info_label)
        
        self.info_btn = QPushButton("ℹ️ Details")
        self.info_btn.setVisible(False)
        self.info_btn.setMaximumWidth(100)
        self.info_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 5px 10px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        self.info_btn.clicked.connect(self._show_device_info_dialog)
        info_container.addWidget(self.info_btn)
        layout.addLayout(info_container)

        # WiFi network list
        net_group = QGroupBox("WiFi Networks")
        net_layout = QVBoxLayout()
        self.network_list = QListWidget()
        self.network_list.itemDoubleClicked.connect(self._on_network_selected)
        net_layout.addWidget(self.network_list)

        self.scan_btn = QPushButton("Scan Networks")
        self.scan_btn.clicked.connect(self._scan_networks)
        net_layout.addWidget(self.scan_btn)
        net_group.setLayout(net_layout)
        layout.addWidget(net_group)

        # Credentials
        cred_group = QGroupBox("WiFi Credentials")
        cred_layout = QGridLayout()
        cred_layout.addWidget(QLabel("SSID:"), 0, 0)
        self.ssid_input = QLineEdit()
        cred_layout.addWidget(self.ssid_input, 0, 1)
        cred_layout.addWidget(QLabel("Password:"), 1, 0)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        cred_layout.addWidget(self.password_input, 1, 1)
        cred_group.setLayout(cred_layout)
        layout.addWidget(cred_group)

        # Status / progress
        self.status_label = QLabel("")
        layout.addWidget(self.status_label)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)  # indeterminate
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        # Buttons
        btn_layout = QHBoxLayout()
        self.provision_btn = QPushButton("Provision")
        self.provision_btn.clicked.connect(self._provision)
        self.provision_btn.setEnabled(False)
        btn_layout.addWidget(self.provision_btn)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)

        self.setLayout(layout)

    def _start_improv(self):
        """Start Improv on the already-open serial port (same as JS: port stays open)."""
        if not self._serial_port or not self._serial_port.is_open:
            self.status_label.setText("Serial port not open")
            return

        # Drain & discard stale console data so the Improv state-machine
        # starts clean.  The read-loop also handles stale bytes via its
        # newline-reset logic, so this is belt-and-suspenders.
        try:
            self._serial_port.reset_input_buffer()
        except (OSError, serial.SerialException) as e:
            self.status_label.setText(f"Port error: {e}")
            return

        from esp_flasher.improv import ImprovManager
        self._improv = ImprovManager(self._serial_port)
        self._improv.state_changed.connect(self._on_state_changed)
        self._improv.error_received.connect(self._on_error)
        self._improv.device_info_received.connect(self._on_device_info)
        self._improv.log_message.connect(self._on_log)
        self._improv.provisioned.connect(self._on_provisioned)
        self._improv.start()

        # Periodically poll for device until it responds
        self._detect_attempts = 0
        self._detect_timer = QTimer(self)
        self._detect_timer.timeout.connect(self._poll_device_state)
        self._detect_timer.start(1000)
        # Also send first request immediately
        QTimer.singleShot(100, self._poll_device_state)

    def _poll_device_state(self):
        """Send request_current_state until device responds or we give up."""
        if not self._improv:
            self._detect_timer.stop()
            return
        if self._improv.device_state is not None:
            # Device has responded, stop polling
            self._detect_timer.stop()
            return
        self._detect_attempts += 1
        if self._detect_attempts > 15:
            self._detect_timer.stop()
            self.status_label.setText("No Improv device detected (timeout)")
            return
        self.status_label.setText(
            f"Detecting Improv device... (attempt {self._detect_attempts}/15)"
        )
        self._improv.request_current_state()

    def _on_state_changed(self, state):
        from esp_flasher.improv import STATE_READY, STATE_PROVISIONING, STATE_PROVISIONED, STATE_NAMES
        name = STATE_NAMES.get(state, f"Unknown ({state})")
        self.progress.setVisible(False)
        if state == STATE_READY:
            self.status_label.setText(f"State: {name}")
            self.provision_btn.setEnabled(True)
            # Auto-request device info
            threading.Thread(target=self._request_info_bg, daemon=True).start()
        elif state == STATE_PROVISIONING:
            self.status_label.setText("Connecting to WiFi...")
            self.provision_btn.setEnabled(False)
            self.progress.setVisible(True)
        elif state == STATE_PROVISIONED:
            if self._is_provisioning:
                self.status_label.setText("✓ WiFi provisioned successfully!")
                self.provision_btn.setEnabled(False)
            else:
                self.status_label.setText("Device already connected to WiFi")
                self.provision_btn.setEnabled(True)
            # Request device info in both cases
            threading.Thread(target=self._request_info_bg, daemon=True).start()

    def _on_error(self, error):
        from esp_flasher.improv import ERROR_NAMES, ERROR_NONE
        if error != ERROR_NONE:
            self.status_label.setText(f"Error: {ERROR_NAMES.get(error, 'Unknown')}")
            self.progress.setVisible(False)
            self.provision_btn.setEnabled(True)

    def _on_device_info(self, info):
        self._device_info = info  # Store for later display
        
        if not info or not any(info):
            self.info_label.setText("Device detected")
            self.info_btn.setVisible(False)
            return
        
        # Show compact summary
        name = info[3] if len(info) > 3 and info[3] else "Unknown"
        chip = info[2] if len(info) > 2 and info[2] else "Unknown"
        self.info_label.setText(f"📱 Device: {name} ({chip})")
        self.info_btn.setVisible(True)
    
    def _show_device_info_dialog(self):
        """Open the detailed device info dialog."""
        if hasattr(self, '_device_info') and self._device_info:
            dialog = DeviceInfoDialog(self._device_info, self)
            dialog.exec()

    def _on_log(self, msg):
        """Show Improv status messages in the dialog's status label."""
        self.status_label.setText(msg)

    def _on_provisioned(self, result):
        self.progress.setVisible(False)
        self.provision_btn.setEnabled(False)
        msg = "✓ WiFi provisioned successfully!"
        if result:
            msg += f"\n{', '.join(result)}"
        self.status_label.setText(msg)

    def _on_network_selected(self, item):
        ssid = item.data(Qt.ItemDataRole.UserRole)
        if ssid:
            self.ssid_input.setText(ssid)
            self.password_input.setFocus()

    def _scan_networks(self):
        if getattr(self, '_scan_in_progress', False):
            return
        self._scan_in_progress = True
        self.scan_btn.setEnabled(False)
        self.network_list.clear()
        self.status_label.setText("Scanning WiFi networks...")
        self.progress.setVisible(True)
        threading.Thread(target=self._scan_bg, daemon=True).start()

    def _scan_bg(self):
        networks = self._improv.request_wifi_networks()
        # Sort by RSSI descending
        networks.sort(key=lambda n: n[1], reverse=True)
        # Thread-safe: emit signal to update UI on main thread
        self._scan_finished.emit(networks)

    def _update_network_list(self, networks):
        self._scan_in_progress = False
        self.scan_btn.setEnabled(True)
        self.network_list.clear()
        self.progress.setVisible(False)
        if not networks:
            self.status_label.setText("No networks found")
            return
        for ssid, rssi, secured in networks:
            lock = "🔒 " if secured else "    "
            item = QListWidgetItem(f"{lock}{ssid}  ({rssi} dBm)")
            item.setData(Qt.ItemDataRole.UserRole, ssid)
            self.network_list.addItem(item)
        self.status_label.setText(f"Found {len(networks)} networks")

    def _request_info_bg(self):
        self._improv.request_device_info()

    def _provision(self):
        ssid = self.ssid_input.text().strip()
        password = self.password_input.text()
        if not ssid:
            self.status_label.setText("Please enter an SSID")
            return
        self._is_provisioning = True
        self.provision_btn.setEnabled(False)
        self.progress.setVisible(True)
        self.status_label.setText(f"Provisioning WiFi: {ssid}...")
        threading.Thread(target=self._provision_bg, args=(ssid, password), daemon=True).start()

    def _provision_bg(self, ssid, password):
        result = self._improv.send_wifi_settings(ssid, password)
        if result is None:
            self._provision_failed_signal.emit()

    def _provision_failed(self):
        self._is_provisioning = False
        self.progress.setVisible(False)
        self.provision_btn.setEnabled(True)
        self.status_label.setText("WiFi provisioning failed")

    def closeEvent(self, event):
        if hasattr(self, '_detect_timer') and self._detect_timer.isActive():
            self._detect_timer.stop()
        if self._improv:
            self._improv.stop()
            self._improv = None
        # Do NOT close the serial port — caller owns it and will restart console reader
        super().closeEvent(event)


class FlashingThread(threading.Thread):
    def __init__(self, firmware, port, finished=None, failed=None):
        threading.Thread.__init__(self)
        self.daemon = True
        self._firmware = firmware
        self._port = port
        self.finished = finished
        self.failed = failed

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
            print(colorize(f"Flashing error: {e}", COLOR_RED))
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
        self.command_history = []  # Store command history
        self.history_index = -1  # Current position in history (-1 = not browsing)
        self.current_input = ""  # Store current input when browsing history
        
        # Initialize settings
        self.settings = QSettings('Tasmota', 'ESP-Flasher')

        self.init_ui()
        # Redirect stdout to colored console
        self._colored_console = ColoredConsole(self.console)
        sys.stdout = self._colored_console
        
        # Connect flash signals
        self.flash_finished.connect(self.on_flash_finished)
        self.flash_failed.connect(self.on_flash_failed)
        
        # Restore window geometry
        self.restore_window_geometry()

    def init_ui(self):
        self.setWindowTitle(f"Tasmota-Esp-Flasher {__version__}")
        # Set default size (will be overridden by saved settings if available)
        self.setGeometry(DEFAULT_WINDOW_X, DEFAULT_WINDOW_Y, 
                        DEFAULT_WINDOW_WIDTH, DEFAULT_WINDOW_HEIGHT)

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
        self.improv_button = QPushButton("Improv WiFi")
        self.improv_button.clicked.connect(self.open_improv)
        actions_layout.addWidget(self.improv_button)
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
        # Install event filter to catch arrow key presses
        self.input_field.installEventFilter(self)
        
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
                self._colored_console.write(colorize("No serial ports found. Please connect a device and click Connect again.", COLOR_YELLOW) + "\n")
    
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
        
        print(colorize(f"Disconnected from {self._port}", COLOR_YELLOW))
    
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
            
            self._colored_console.write(colorize(f"Connected to {self._port} at 115200 baud", COLOR_GREEN) + "\n")
            
        except Exception as e:
            self.show_log_error(f"Failed to open serial port: {e}")
            self.stop_serial()
            self.connect_button.setText("Connect")
            self.connect_button.setStyleSheet("")
            self.port_combobox.setEnabled(True)

    def pick_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Select Firmware File", "", "Binary Files (*.bin);;All Files (*)")
        if file_name:
            self._firmware = file_name
            self.firmware_button.setText(file_name)

    def flash_esp(self):
        if self._is_flashing:
            self.show_log_error("Flashing already in progress")
            return
            
        if not self._firmware or not self._port:
            if not self._port:
                print(colorize("No serial port selected!", COLOR_RED))
            if not self._firmware:
                print(colorize("No firmware file selected!", COLOR_RED))
            return
        
        # Remember if we were connected
        self._was_connected_before_flash = self._serial_port and self._serial_port.is_open
        
        # IMPORTANT: Completely disconnect and wait for port to be released
        if self._was_connected_before_flash:
            print(colorize("Disconnecting from serial port for flashing...", COLOR_YELLOW))
            self.disconnect_from_port()
            
            # Give the OS time to release the port
            from PyQt6.QtCore import QTimer
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
        self._flash_worker = FlashingThread(
            self._firmware, 
            self._port,
            finished=self.flash_finished,
            failed=self.flash_failed
        )
        self._flash_worker.start()
    
    def open_improv(self):
        """Open Improv WiFi provisioning dialog.
        Matches JS: stop console reader, pass open port to Improv, restart reader on close."""
        if self._is_flashing:
            self.show_log_error("Cannot use Improv while flashing")
            return
        if not self._serial_port or not self._serial_port.is_open:
            self.show_log_error("Connect to a serial port first")
            return

        # Stop console reader — mute signals first to prevent cross-thread
        # queued events from being delivered, then stop thread, then disconnect
        # and flush the Qt event queue so no stale events remain.
        if self._serial_reader:
            self._serial_reader.stop()  # sets _muted=True and running=False, joins thread
            self._serial_reader.line_received.disconnect(self.append_log_line)
            self._serial_reader.error_occurred.disconnect(self.handle_serial_error)
            # Flush any already-queued cross-thread events so they are discarded
            from PyQt6.QtWidgets import QApplication
            QApplication.processEvents()
            self._serial_reader = None

        # Disable console input while in Improv mode
        self.input_field.setEnabled(False)
        self.send_button.setEnabled(False)

        # Open Improv dialog with the same open port (port stays open, no ESP reset)
        dlg = ImprovDialog(self._serial_port, parent=self)
        dlg.exec()

        # Restart console reader on the same open port (like JS reconnectConsole)
        if self._serial_port and self._serial_port.is_open:
            from esp_flasher.serial_console import SerialReader
            self._serial_reader = SerialReader(self._serial_port)
            self._serial_reader.line_received.connect(self.append_log_line)
            self._serial_reader.error_occurred.connect(self.handle_serial_error)
            self._serial_reader.start()
            self.input_field.setEnabled(True)
            self.send_button.setEnabled(True)

    def on_flash_finished(self):
        """Called when flashing is complete"""
        print(colorize("\nFlashing complete!", COLOR_GREEN))
        
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
        print(colorize("\nFlashing failed!", COLOR_RED))
        
        # Clear flashing flag and re-enable UI
        self._is_flashing = False
        self.flash_button.setEnabled(True)
        self.connect_button.setEnabled(True)
        if not (self._serial_port and self._serial_port.is_open):
            self.port_combobox.setEnabled(True)
    
    def _reconnect_after_flash(self):
        """Reconnect to serial port after flash"""
        self.connect_to_port()
        if not (self._serial_port and self._serial_port.is_open):
            self.port_combobox.setEnabled(True)
    
    def stop_serial(self):
        """Stop serial communication"""
        # Stop reader thread first
        if self._serial_reader:
            self._serial_reader.stop()
            self._serial_reader = None
        
        # Close serial port and schedule cleanup
        if self._serial_port:
            try:
                if self._serial_port.is_open:
                    self._serial_port.close()
            except Exception as e:
                print(f"Error closing serial port: {e}")
            
            # Schedule cleanup after port release using non-blocking timer
            from PyQt6.QtCore import QTimer
            QTimer.singleShot(100, self._finish_serial_cleanup)
        else:
            self._finish_serial_cleanup()
    
    def _finish_serial_cleanup(self):
        """Complete serial port cleanup after release delay"""
        self._serial_port = None
        
        # Disable input controls (check if they exist first)
        if hasattr(self, 'input_field'):
            self.input_field.setEnabled(False)
            self.input_field.setPlaceholderText("Type command and press Enter (connect to device first)...")
        if hasattr(self, 'send_button'):
            self.send_button.setEnabled(False)
    
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
            
            # Add to command history (avoid duplicates of last command)
            if not self.command_history or self.command_history[-1] != command:
                self.command_history.append(command)
                # Limit history to 100 commands
                if len(self.command_history) > 100:
                    self.command_history.pop(0)
            
            # Reset history navigation
            self.history_index = -1
            self.current_input = ""
            
            # Echo command to console
            self._colored_console.write(colorize(f"> {command}", COLOR_CYAN) + "\n")
            
            # Clear input field
            self.input_field.clear()
            
        except Exception as e:
            self.handle_serial_error(f"Failed to send command: {e}")
    
    def eventFilter(self, obj, event):
        """Filter events to catch arrow key presses in input field"""
        if obj == self.input_field and event.type() == event.Type.KeyPress:
            
            if event.key() == Qt.Key.Key_Up:
                # Navigate up in history (older commands)
                self.navigate_history_up()
                return True
            elif event.key() == Qt.Key.Key_Down:
                # Navigate down in history (newer commands)
                self.navigate_history_down()
                return True
        
        return super().eventFilter(obj, event)
    
    def navigate_history_up(self):
        """Navigate to previous command in history"""
        if not self.command_history:
            return
        
        # First time pressing up - save current input
        if self.history_index == -1:
            self.current_input = self.input_field.text()
            self.history_index = len(self.command_history)
        
        # Move up in history
        if self.history_index > 0:
            self.history_index -= 1
            self.input_field.setText(self.command_history[self.history_index])
    
    def navigate_history_down(self):
        """Navigate to next command in history"""
        if self.history_index == -1:
            return  # Not browsing history
        
        # Move down in history
        self.history_index += 1
        
        if self.history_index >= len(self.command_history):
            # Reached the end - restore current input
            self.history_index = -1
            self.input_field.setText(self.current_input)
        else:
            self.input_field.setText(self.command_history[self.history_index])
    
    def append_log_line(self, line):
        """Append a line to the console"""
        # Preserve bare \r for progress indicators
        if line.endswith("\r"):
            self._colored_console.write(line)
        else:
            self._colored_console.write(line + "\n")
    
    def show_log_error(self, message):
        """Show error message in console"""
        self._colored_console.write(colorize(message, COLOR_RED) + "\n")
    
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
    
    def restore_window_geometry(self):
        """Restore window size and position from settings"""
        geometry = self.settings.value('window/geometry')
        if geometry:
            self.restoreGeometry(geometry)
    
    def save_window_geometry(self):
        """Save window size and position to settings"""
        self.settings.setValue('window/geometry', self.saveGeometry())
    
    def closeEvent(self, event):
        """Handle window close event"""
        if self._is_flashing:
            self.show_log_error("Cannot close window while flashing is in progress")
            event.ignore()
            return
        
        # Save window geometry before closing
        self.save_window_geometry()
            
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
    palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.Base, QColor(35, 35, 35))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.Text, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 0, 0))
    palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(0, 0, 0))
    app.setPalette(palette)

    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
