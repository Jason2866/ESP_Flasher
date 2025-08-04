# Big thx to Michael Kandziora for this GUI port to PyQt5
import re
import sys
import threading
import os
import platform
import distro

from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QPushButton, QLabel, QComboBox,
                             QFileDialog, QTextEdit, QGroupBox, QGridLayout)
from PyQt5.QtGui import QColor, QTextCursor, QPalette, QColor
from PyQt5.QtCore import pyqtSignal, QObject

from esp_flasher.own_esptool import get_port_list
from esp_flasher.const import __version__

COLOR_RE = re.compile(r'(?:\033)(?:\[(.*?)[@-~]|\].*?(?:\007|\033\\))')
COLORS = {
    'black': QColor('black'),
    'red': QColor('red'),
    'green': QColor('green'),
    'yellow': QColor('yellow'),
    'blue': QColor('blue'),
    'magenta': QColor('magenta'),
    'cyan': QColor('cyan'),
    'white': QColor('white'),
}
FORE_COLORS = {**COLORS, None: QColor('white')}
BACK_COLORS = {**COLORS, None: QColor('black')}

class RedirectText(QObject):
    text_written = pyqtSignal(str)

    def __init__(self, text_edit):
        super().__init__()
        self._out = text_edit
        self._line = ''
        self._bold = False
        self._italic = False
        self._underline = False
        self._foreground = None
        self._background = None
        self._secret = False
        self.text_written.connect(self._append_text)

    def write(self, string):
        self.text_written.emit(string)

    def flush(self):
        pass

    def _append_text(self, text):
        cursor = self._out.textCursor()
        self._out.moveCursor(QTextCursor.End)
        self._out.insertPlainText(text)
        self._out.setTextCursor(cursor)

class FlashingThread(threading.Thread):
    def __init__(self, firmware, port, show_logs=False):
        threading.Thread.__init__(self)
        self.daemon = True
        self._firmware = firmware
        self._port = port
        self._show_logs = show_logs

    def run(self):
        try:
            from esp_flasher.__main__ import run_esp_flasher

            argv = ['esp_flasher', '--port', self._port, self._firmware]
            if self._show_logs:
                argv.append('--show-logs')
            run_esp_flasher(argv)
        except Exception as e:
            print("Unexpected error: {}".format(e))
            raise

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self._firmware = None
        self._port = None

        self.init_ui()
        sys.stdout = RedirectText(self.console)  # Redirect stdout to console

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
        self.reload_ports()
        self.port_combobox.currentIndexChanged.connect(self.select_port)
        reload_button = QPushButton("Reload")
        reload_button.clicked.connect(self.reload_ports)
        port_layout.addWidget(port_label, 0, 0)
        port_layout.addWidget(self.port_combobox, 0, 1)
        port_layout.addWidget(reload_button, 0, 2)
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
        self.logs_button = QPushButton("View Logs")
        self.logs_button.clicked.connect(self.view_logs)
        actions_layout.addWidget(self.flash_button)
        actions_layout.addWidget(self.logs_button)
        actions_group_box.setLayout(actions_layout)

        console_group_box = QGroupBox("Console")
        console_layout = QVBoxLayout()
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        console_layout.addWidget(self.console)
        console_group_box.setLayout(console_layout)

        vbox.addWidget(port_group_box)
        vbox.addWidget(firmware_group_box)
        vbox.addWidget(actions_group_box)
        vbox.addWidget(console_group_box)

        central_widget.setLayout(vbox)

    def reload_ports(self):
        self.port_combobox.clear()
        ports = get_port_list()
        if ports:
            self.port_combobox.addItems(ports)
            self._port = ports[0]
        else:
            self.port_combobox.addItem("")

    def select_port(self, index):
        self._port = self.port_combobox.itemText(index)

    def pick_file(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Select Firmware File", "", "Binary Files (*.bin);;All Files (*)", options=options)
        if file_name:
            self._firmware = file_name
            self.firmware_button.setText(file_name)

    def flash_esp(self):
        self.console.clear()
        if self._firmware and self._port:
            worker = FlashingThread(self._firmware, self._port)
            worker.start()

    def view_logs(self):
        self.console.clear()
        if self._port:
            worker = FlashingThread('dummy', self._port, show_logs=True)
            worker.start()

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
