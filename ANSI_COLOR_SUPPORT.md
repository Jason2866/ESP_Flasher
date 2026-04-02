# ANSI Color Support in ESP-Flasher

ESP-Flasher now supports ANSI color codes and text formatting in the terminal output.

## Features

The console now supports the following ANSI escape sequences:

### Text Formatting
- **Bold** (`\033[1m`)
- *Italic* (`\033[3m`)
- <u>Underline</u> (`\033[4m`)
- ~~Strikethrough~~ (`\033[9m`)

### Foreground Colors
- Black (`\033[30m`)
- Red (`\033[31m`)
- Green (`\033[32m`)
- Yellow (`\033[33m`)
- Blue (`\033[34m`)
- Magenta (`\033[35m`)
- Cyan (`\033[36m`)
- White (`\033[37m`)
- Default (`\033[39m`)

### Background Colors
- Black (`\033[40m`)
- Red (`\033[41m`)
- Green (`\033[42m`)
- Yellow (`\033[43m`)
- Blue (`\033[44m`)
- Magenta (`\033[45m`)
- Cyan (`\033[46m`)
- White (`\033[47m`)
- Default (`\033[49m`)

### Special Features
- **Reset all formatting**: `\033[0m`
- **Secret text**: `\033[5m` (hidden from selection, shows as `[redacted]`)
- **Carriage return handling**: Properly handles `\r` for progress indicators

## Implementation

The ANSI color support is implemented in `esp_flasher/console_color.py` using the `ColoredConsole` class, which:

1. Parses ANSI escape sequences using regex
2. Maintains formatting state (bold, italic, colors, etc.)
3. Applies formatting using Qt's `QTextCharFormat`
4. Handles carriage returns for overwriting lines
5. Auto-scrolls to bottom when new content is added

## Testing

You can test the ANSI color support by running:

```bash
python test_ansi_colors.py
```

This will display various colored and formatted text examples in the console.

## Usage Example

```python
# Print colored text
print("\033[32mSuccess!\033[0m")  # Green text
print("\033[31mError!\033[0m")    # Red text
print("\033[1;33mWarning!\033[0m") # Bold yellow text

# Combine formatting
print("\033[1;4;36mBold underlined cyan text\033[0m")

# Background colors
print("\033[37;41mWhite text on red background\033[0m")
```

## Technical Details

- **Regex Pattern**: `(?:\x1B|\033)(?:\[(.*?)[@-~]|\].*?(?:\x07|\x1B\\))`
- **Supported Codes**: SGR (Select Graphic Rendition) codes 0-49
- **Qt Integration**: Uses `QTextCharFormat` for applying formatting
- **Thread-Safe**: Uses Qt signals for cross-thread communication
