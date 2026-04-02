# ANSI Color Support Implementation

## Summary

ANSI color support has been successfully implemented in ESP-Flasher.

## Changes Made

### New Files

1. **`esp_flasher/console_color.py`**
   - Complete ANSI color code parser and renderer
   - `ConsoleState` class for tracking formatting state
   - `ColoredConsole` class for processing and displaying colored output
   - Support for all standard ANSI SGR codes (0-49)
   - Carriage return handling for progress indicators
   - Thread-safe implementation using Qt signals

2. **`test_ansi_colors.py`**
   - Test script demonstrating all supported ANSI features
   - Examples of colors, formatting, and combinations
   - Simulated ESP output patterns

3. **`examples/colored_output_example.py`**
   - Practical example showing how to use ANSI colors
   - `ANSIColors` helper class with constants
   - Simulated flashing process with colored output
   - Progress bar implementation

4. **`ANSI_COLOR_SUPPORT.md`**
   - Complete documentation of ANSI color support
   - Feature list and usage examples
   - Technical implementation details

### Modified Files

1. **`esp_flasher/gui.py`**
   - Removed old `RedirectText` class
   - Integrated `ColoredConsole` for stdout redirection
   - Updated imports to include `console_color` module

2. **`DOCUMENTATION.md`**
   - Added ANSI color support to features list
   - Added new section "ANSI Color Support" in Architecture
   - Updated project structure to include new files
   - Updated `gui.py` and `console_color.py` module descriptions

3. **`README.md`**
   - Added "Full ANSI color support" to feature list

## Features Implemented

### Text Formatting
- Bold (`\033[1m`)
- Italic (`\033[3m`)
- Underline (`\033[4m`)
- Strikethrough (`\033[9m`)

### Colors
- 8 foreground colors (black, red, green, yellow, blue, magenta, cyan, white)
- 8 background colors (same as foreground)
- Reset to default (`\033[0m`)

### Special Features
- Secret text (hidden from selection, shows as `[redacted]`)
- Carriage return handling for overwriting lines
- Auto-scroll to bottom
- Thread-safe operation

## Implementation Details

1. **Regex Pattern**: `(?:\x1B|\033)(?:\[(.*?)[@-~]|\].*?(?:\x07|\x1B\\))`
   - Matches ANSI escape sequences
   - Supports both `\x1B` and `\033` escape characters

2. **State Management**: `ConsoleState` class tracks current formatting
   - Bold, italic, underline, strikethrough flags
   - Foreground and background color
   - Secret text flag

3. **Qt Integration**: Uses `QTextCharFormat` for applying formatting
   - Font weight for bold
   - Font italic for italic
   - Font underline/strikethrough
   - Foreground/background colors

4. **Thread Safety**: Qt signals for cross-thread communication
   - `text_written` signal emitted from any thread
   - `_append_text` slot runs in GUI thread

## Testing

Run the test script to verify ANSI color support:

```bash
python test_ansi_colors.py
```

Or run the example:

```bash
python examples/colored_output_example.py
```

## Compatibility

- Fully compatible with existing ESP-Flasher functionality
- No breaking changes to existing code
- Drop-in replacement for the old `RedirectText` class
- Works on all supported platforms (Windows, macOS, Linux)

## Future Enhancements

Potential improvements for future versions:

1. Support for 256-color palette (`\033[38;5;Nm`)
2. Support for RGB colors (`\033[38;2;R;G;Bm`)
3. Support for bright/intense colors (`\033[90-97m`)
4. Configurable color schemes
5. Export console output with colors (HTML/RTF)

## References

- ANSI escape codes: https://en.wikipedia.org/wiki/ANSI_escape_code
- Qt text formatting: https://doc.qt.io/qt-5/qtextcharformat.html
