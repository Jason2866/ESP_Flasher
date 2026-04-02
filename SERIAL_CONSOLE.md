# Interactive Serial Console

ESP-Flasher now includes an interactive serial console with command input support.

## Features

### Console Output
- **ANSI color support** — Full support for colored and formatted text
- **Automatic timestamps** — Each line is prefixed with `[HH:MM:SS]`
- **Thread-safe reading** — Serial data is read in a background thread
- **Auto-scroll** — Console automatically scrolls to show new content

### Command Input
- **Input field** — Type commands directly in the GUI
- **Enter to send** — Press Enter or click Send button
- **Command echo** — Sent commands are displayed in cyan color
- **Clear button** — Clear the console output

### Serial Communication
- **Configurable baud rate** — Default 115200, can be changed
- **Automatic reconnection** — Handles port disconnections gracefully
- **Error handling** — Shows errors in red color
- **Clean shutdown** — Properly closes serial port on exit

## Usage

### GUI Mode

1. **Click "Connect"** — Loads available ports and connects to selected port (button turns green)
2. **Serial Monitor Active** — You can now send commands to your device
3. **Optional: Select different port** — Choose from dropdown and click "Connect" again
4. **Optional: Select Firmware** — Browse for your `.bin` file (only needed for flashing)
5. **Optional: Click "Flash ESP"** — Starts flashing
   - Disconnects from serial port
   - Flashes firmware
   - Immediately reconnects when done (no delay)
   - Serial monitor becomes active again
6. **Type Commands** — Enter commands in the input field and press Enter anytime
7. **Click "Disconnect"** — Close the connection when done (button turns gray)

### Keyboard Shortcuts

- **Enter** — Send command
- **Click anywhere in console** — Focus input field (if no text is selected)

## Implementation Details

### Architecture

The serial console is implemented using two main components:

1. **SerialReader** — Background thread that reads from serial port
   - Runs in daemon thread
   - Emits Qt signals for thread-safe communication
   - Handles serial exceptions gracefully

2. **GUI Integration** — Main window manages serial communication
   - Console output area (QTextEdit with ColoredConsole)
   - Dynamic input field (QLineEdit) that appears when viewing logs
   - Send and Clear buttons
   - Manages serial port lifecycle

### Thread Safety

All serial communication is thread-safe:
- Serial reading happens in background thread
- Qt signals/slots ensure GUI updates happen in main thread
- Proper locking prevents race conditions

### Error Handling

The console handles various error conditions:
- Serial port not available
- Device disconnected during operation
- Invalid baud rate
- Write failures

All errors are displayed in the console with red color.

## Code Example

Using the SerialConsoleWidget in your own application:

```python
from PyQt5.QtWidgets import QApplication, QMainWindow
from esp_flasher.serial_console import SerialConsoleWidget

app = QApplication([])
window = QMainWindow()

# Create serial console
console = SerialConsoleWidget()
window.setCentralWidget(console)

# Start serial communication
console.start_serial('/dev/ttyUSB0', baudrate=115200)

window.show()
app.exec_()

# Clean up
console.stop_serial()
```

## Troubleshooting

### Console not receiving data
- Check that the correct serial port is selected
- Verify the baud rate matches your device (default: 115200)
- Ensure no other application is using the serial port

### Commands not being sent
- Check that the serial port is open (input field should be enabled)
- Verify the device is in a state to receive commands
- Check for error messages in the console

### Colors not displaying correctly
- ANSI color support is automatic
- If colors don't appear, check that your device is sending ANSI codes
- Test with the `test_ansi_colors.py` script

### Port access denied (Linux)
Add your user to the dialout group:
```bash
sudo usermod -a -G dialout $(whoami)
```
Then log out and log back in.

## Future Enhancements

Potential improvements for future versions:

1. **Command history** — Up/Down arrows to recall previous commands
2. **Auto-completion** — Suggest commands based on history
3. **Configurable baud rate** — Change baud rate without reconnecting
4. **Save logs** — Export console output to file
5. **Filters** — Show/hide specific log levels
6. **Hex view** — Display raw bytes in hexadecimal
7. **Line endings** — Configurable line ending (CR, LF, CRLF)
8. **Local echo** — Option to disable command echo

## References
- PySerial documentation: https://pyserial.readthedocs.io/
- Qt Serial Port: https://doc.qt.io/qt-5/qtserialport-index.html
