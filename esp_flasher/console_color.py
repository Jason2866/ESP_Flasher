"""
ANSI Color Console Support for ESP-Flasher
"""

from PyQt5.QtWidgets import QTextEdit
from PyQt5.QtGui import QColor, QTextCursor, QTextCharFormat, QFont
from PyQt5.QtCore import QObject, pyqtSignal
import re


class ConsoleState:
    """Tracks the current text formatting state"""
    def __init__(self):
        self.bold = False
        self.italic = False
        self.underline = False
        self.strikethrough = False
        self.foreground_color = None
        self.background_color = None
        self.secret = False

    def reset(self):
        """Reset all formatting to defaults"""
        self.bold = False
        self.italic = False
        self.underline = False
        self.strikethrough = False
        self.foreground_color = None
        self.background_color = None
        self.secret = False


class ColoredConsole(QObject):
    """
    A console widget that supports ANSI color codes and text formatting.
    
    Supports:
    - Bold, italic, underline, strikethrough
    - Foreground and background colors (standard 8 colors)
    - Secret text (hidden from selection)
    - Carriage return handling
    """
    
    text_written = pyqtSignal(str)
    
    # ANSI color mapping
    COLORS = {
        'black': QColor(128, 128, 128),
        'red': QColor(255, 0, 0),
        'green': QColor(0, 255, 0),
        'yellow': QColor(255, 255, 0),
        'blue': QColor(0, 0, 255),
        'magenta': QColor(255, 0, 255),
        'cyan': QColor(0, 255, 255),
        'white': QColor(187, 187, 187),
    }
    
    def __init__(self, text_edit: QTextEdit):
        super().__init__()
        self.text_edit = text_edit
        self.state = ConsoleState()
        self.carriage_return = False
        self.text_written.connect(self._append_text)
        
    def write(self, text: str):
        """Write text to the console (for stdout redirection)"""
        self.text_written.emit(text)
    
    def flush(self):
        """Flush the output (no-op for compatibility)"""
        pass
    
    def logs(self) -> str:
        """Get all text from the console"""
        return self.text_edit.toPlainText()
    
    def clear(self):
        """Clear the console and reset parser state"""
        self.state.reset()
        self.carriage_return = False
        self.text_edit.clear()
    
    def _append_text(self, line: str):
        """Append text with ANSI code processing"""
        # ANSI escape sequence regex
        # Matches: ESC[...m (SGR - Select Graphic Rendition)
        # Also matches: ESC]...BEL or ESC]...ESC\ (OSC - Operating System Command)
        ansi_re = re.compile(r'(?:\x1B|\033)(?:\[(.*?)m|\].*?(?:\x07|\x1B\\))')
        
        # Check if we should auto-scroll (before adding text)
        scrollbar = self.text_edit.verticalScrollBar()
        should_autoscroll = scrollbar.value() >= scrollbar.maximum() - 10
        
        # Handle carriage return from previous line
        if self.carriage_return:
            if line != "\n":  # don't remove if \r\n
                # Remove last line
                cursor = self.text_edit.textCursor()
                cursor.movePosition(QTextCursor.End)
                cursor.select(QTextCursor.LineUnderCursor)
                cursor.removeSelectedText()
                cursor.deletePreviousChar()  # Remove the newline
            self.carriage_return = False
        
        # Check if line ends with bare CR (not \r\n)
        has_bare_cr = line.endswith("\r") and not line.endswith("\r\n")
        if has_bare_cr:
            self.carriage_return = True
            line = "\n" + line[:-1]  # own line for bar, strip trailing \r
        
        # Move cursor to end
        cursor = self.text_edit.textCursor()
        cursor.movePosition(QTextCursor.End)
        
        # Process the line with ANSI codes
        i = 0
        for match in ansi_re.finditer(line):
            j = match.start()
            
            # Add text before the ANSI code
            if i < j:
                self._add_span(cursor, line[i:j])
            
            i = match.end()
            
            # Process ANSI code
            if match.group(1) is not None:
                self._process_ansi_code(match.group(1))
        
        # Add remaining text
        if i < len(line):
            self._add_span(cursor, line[i:])
        
        # Set the cursor to make it visible
        self.text_edit.setTextCursor(cursor)
        
        # Auto-scroll to bottom if we were at the bottom before
        if should_autoscroll:
            self.text_edit.ensureCursorVisible()
            scrollbar.setValue(scrollbar.maximum())
    
    def _add_span(self, cursor: QTextCursor, content: str):
        """Add text with current formatting"""
        if not content:
            return
        
        # Create text format based on current state
        fmt = QTextCharFormat()
        
        if self.state.bold:
            fmt.setFontWeight(QFont.Bold)
        
        if self.state.italic:
            fmt.setFontItalic(True)
        
        if self.state.underline and self.state.strikethrough:
            fmt.setFontUnderline(True)
            fmt.setFontStrikeOut(True)
        elif self.state.underline:
            fmt.setFontUnderline(True)
        elif self.state.strikethrough:
            fmt.setFontStrikeOut(True)
        
        if self.state.foreground_color is not None:
            fmt.setForeground(self.COLORS.get(self.state.foreground_color, QColor(255, 255, 255)))
        
        if self.state.background_color is not None:
            fmt.setBackground(self.COLORS.get(self.state.background_color, QColor(0, 0, 0)))
        
        # Insert text with formatting
        if self.state.secret:
            # For secret text, insert placeholder
            cursor.insertText("[redacted]", fmt)
        else:
            cursor.insertText(content, fmt)
    
    def _process_ansi_code(self, code_str: str):
        """Process ANSI SGR (Select Graphic Rendition) codes"""
        # Empty string means reset (SGR 0)
        if not code_str:
            self.state.reset()
            return
        
        # Split multiple codes separated by semicolon
        for code in code_str.split(';'):
            # Empty segment means reset (SGR 0)
            if not code:
                self.state.reset()
                continue
            
            try:
                code_num = int(code)
            except ValueError:
                continue
            
            # Process the code
            if code_num == 0:
                # Reset all attributes
                self.state.reset()
            elif code_num == 1:
                self.state.bold = True
            elif code_num == 3:
                self.state.italic = True
            elif code_num == 4:
                self.state.underline = True
            elif code_num == 5:
                pass  # Blink (not implemented)
            elif code_num == 6:
                pass  # Rapid blink (not implemented)
            elif code_num == 8:
                self.state.secret = True  # Conceal
            elif code_num == 9:
                self.state.strikethrough = True
            elif code_num == 22:
                self.state.bold = False
            elif code_num == 23:
                self.state.italic = False
            elif code_num == 24:
                self.state.underline = False
            elif code_num == 28:
                self.state.secret = False  # Reveal
            elif code_num == 29:
                self.state.strikethrough = False
            # Foreground colors
            elif code_num == 30:
                self.state.foreground_color = 'black'
            elif code_num == 31:
                self.state.foreground_color = 'red'
            elif code_num == 32:
                self.state.foreground_color = 'green'
            elif code_num == 33:
                self.state.foreground_color = 'yellow'
            elif code_num == 34:
                self.state.foreground_color = 'blue'
            elif code_num == 35:
                self.state.foreground_color = 'magenta'
            elif code_num == 36:
                self.state.foreground_color = 'cyan'
            elif code_num == 37:
                self.state.foreground_color = 'white'
            elif code_num == 39:
                self.state.foreground_color = None
            # Background colors
            elif code_num == 40:
                self.state.background_color = 'black'
            elif code_num == 41:
                self.state.background_color = 'red'
            elif code_num == 42:
                self.state.background_color = 'green'
            elif code_num == 43:
                self.state.background_color = 'yellow'
            elif code_num == 44:
                self.state.background_color = 'blue'
            elif code_num == 45:
                self.state.background_color = 'magenta'
            elif code_num == 46:
                self.state.background_color = 'cyan'
            elif code_num == 47:
                self.state.background_color = 'white'
            elif code_num == 49:
                self.state.background_color = None
