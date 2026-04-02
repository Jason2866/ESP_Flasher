#!/usr/bin/env python3
"""
Example demonstrating how to use ANSI colors in ESP-Flasher output
"""


class ANSIColors:
    """ANSI color code constants for easy use"""
    
    # Reset
    RESET = '\033[0m'
    
    # Text styles
    BOLD = '\033[1m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    STRIKETHROUGH = '\033[9m'
    
    # Foreground colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Background colors
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'


def print_status(message, status='info'):
    """Print a status message with appropriate color"""
    colors = {
        'info': ANSIColors.CYAN,
        'success': ANSIColors.GREEN,
        'warning': ANSIColors.YELLOW,
        'error': ANSIColors.RED,
    }
    color = colors.get(status, ANSIColors.WHITE)
    print(f"{color}{message}{ANSIColors.RESET}")


def print_progress(current, total, message=''):
    """Print a progress indicator"""
    percentage = (current / total) * 100
    bar_length = 40
    filled = int(bar_length * current / total)
    bar = '█' * filled + '░' * (bar_length - filled)
    
    color = ANSIColors.GREEN if percentage == 100 else ANSIColors.CYAN
    print(f"\r{color}[{bar}] {percentage:.1f}% {message}{ANSIColors.RESET}", end='')
    if percentage == 100:
        print()  # New line when complete


def simulate_flashing():
    """Simulate ESP flashing with colored output"""
    import time
    
    print(f"\n{ANSIColors.BOLD}ESP-Flasher - Colored Output Example{ANSIColors.RESET}\n")
    
    # Connection phase
    print_status("Connecting to ESP32...", 'info')
    time.sleep(0.5)
    print_status("✓ Connected successfully", 'success')
    
    # Detection phase
    print_status("Detecting chip type...", 'info')
    time.sleep(0.5)
    print(f"{ANSIColors.CYAN}Chip: {ANSIColors.BOLD}ESP32-D0WD-V3{ANSIColors.RESET}")
    print(f"{ANSIColors.CYAN}MAC: {ANSIColors.BOLD}AA:BB:CC:DD:EE:FF{ANSIColors.RESET}")
    print(f"{ANSIColors.CYAN}Flash Size: {ANSIColors.BOLD}4MB{ANSIColors.RESET}")
    
    # Erase phase
    print()
    print_status("Erasing flash...", 'warning')
    for i in range(1, 11):
        print_progress(i, 10, "Erasing")
        time.sleep(0.1)
    print_status("✓ Flash erased", 'success')
    
    # Write phase
    print()
    print_status("Writing firmware...", 'info')
    for i in range(1, 21):
        print_progress(i, 20, "Writing")
        time.sleep(0.1)
    print_status("✓ Firmware written", 'success')
    
    # Verify phase
    print()
    print_status("Verifying...", 'info')
    time.sleep(0.5)
    print_status("✓ Verification successful", 'success')
    
    # Complete
    print()
    print(f"{ANSIColors.BOLD}{ANSIColors.GREEN}✓ Flashing complete!{ANSIColors.RESET}")
    print()
    
    # Show some example log output
    print(f"{ANSIColors.BOLD}Device Logs:{ANSIColors.RESET}")
    print(f"{ANSIColors.CYAN}[12:34:56] {ANSIColors.RESET}System starting...")
    print(f"{ANSIColors.GREEN}[12:34:57] {ANSIColors.RESET}WiFi connected")
    print(f"{ANSIColors.YELLOW}[12:34:58] {ANSIColors.RESET}Warning: Low memory")
    print(f"{ANSIColors.RED}[12:34:59] {ANSIColors.RESET}Error: Sensor timeout")
    print()


if __name__ == "__main__":
    simulate_flashing()
