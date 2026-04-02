#!/usr/bin/env python3
"""
Example demonstrating the Serial Console with input support
This shows how to use the SerialConsoleWidget for interactive serial communication
"""

import sys
from pathlib import Path
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget
from PyQt5.QtGui import QPalette, QColor

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from esp_flasher.serial_console import SerialConsoleWidget


class SerialConsoleDemo(QMainWindow):
    """Demo window showing the serial console widget"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle("Serial Console Demo")
        self.setGeometry(100, 100, 800, 600)
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create layout
        layout = QVBoxLayout()
        
        # Create serial console widget
        self.serial_console = SerialConsoleWidget()
        layout.addWidget(self.serial_console)
        
        central_widget.setLayout(layout)
        
        # Uncomment to auto-connect to a serial port
        # self.serial_console.start_serial('/dev/ttyUSB0', baudrate=115200)
    
    def closeEvent(self, event):
        """Handle window close"""
        self.serial_console.stop_serial()
        super().closeEvent(event)


def main():
    app = QApplication(sys.argv)
    
    # Set dark theme
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
    
    # Create and show window
    window = SerialConsoleDemo()
    window.show()
    
    print("\n" + "="*60)
    print("Serial Console Demo")
    print("="*60)
    print("\nFeatures:")
    print("  - View serial output with ANSI color support")
    print("  - Send commands to the device")
    print("  - Timestamps for each line")
    print("  - Clear console button")
    print("\nUsage:")
    print("  1. Uncomment the auto-connect line in the code")
    print("  2. Change '/dev/ttyUSB0' to your serial port")
    print("  3. Run the script")
    print("  4. Type commands in the input field and press Enter")
    print("\nOr modify the SerialConsoleWidget to add a port selector")
    print("="*60 + "\n")
    
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
