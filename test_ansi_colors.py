#!/usr/bin/env python3
"""
Demo script to demonstrate ANSI color support in ESP-Flasher
"""

# Prevent pytest from collecting this module
__test__ = False

def demo_ansi_colors():
    """Print various ANSI color codes to test the console"""
    
    print("\n=== Testing ANSI Color Support ===\n")
    
    # Test basic colors
    print("\033[31mRed text\033[0m")
    print("\033[32mGreen text\033[0m")
    print("\033[33mYellow text\033[0m")
    print("\033[34mBlue text\033[0m")
    print("\033[35mMagenta text\033[0m")
    print("\033[36mCyan text\033[0m")
    print("\033[37mWhite text\033[0m")
    
    # Test bold
    print("\n\033[1mBold text\033[0m")
    print("\033[1;31mBold red text\033[0m")
    
    # Test italic
    print("\n\033[3mItalic text\033[0m")
    print("\033[3;32mItalic green text\033[0m")
    
    # Test underline
    print("\n\033[4mUnderlined text\033[0m")
    print("\033[4;33mUnderlined yellow text\033[0m")
    
    # Test strikethrough
    print("\n\033[9mStrikethrough text\033[0m")
    
    # Test background colors
    print("\n\033[41mRed background\033[0m")
    print("\033[42mGreen background\033[0m")
    print("\033[43mYellow background\033[0m")
    print("\033[44mBlue background\033[0m")
    
    # Test combinations
    print("\n\033[1;4;31mBold underlined red text\033[0m")
    print("\033[3;32;44mItalic green text on blue background\033[0m")
    
    # Test typical ESP output patterns
    print("\n=== Simulating ESP Output ===\n")
    print("\033[32mConnecting....\033[0m")
    print("\033[33mDetecting chip type... ESP32\033[0m")
    print("\033[36mChip is ESP32-D0WD-V3 (revision v3.0)\033[0m")
    print("\033[32mFlash will be erased from 0x00001000 to 0x00005fff...\033[0m")
    print("\033[1;32mFlash complete!\033[0m")
    print("\033[31mError: Connection failed\033[0m")
    
    # Test bare reset sequence
    print("\n=== Testing Parser Edge Cases ===\n")
    print("\033[mBare reset (ESC[m)\033[0m")
    
    # Test conceal/reveal
    print("\033[8mThis text is concealed\033[28m and this is revealed\033[0m")
    
    # Test carriage return (progress indicator simulation)
    import sys
    sys.stdout.write("\033[33mProgress: [          ] 0%\r")
    sys.stdout.flush()
    import time
    time.sleep(0.5)
    sys.stdout.write("\033[33mProgress: [#####     ] 50%\r")
    sys.stdout.flush()
    time.sleep(0.5)
    sys.stdout.write("\033[32mProgress: [##########] 100%\033[0m\n")
    sys.stdout.flush()
    
    # Test mixed CR with ANSI codes
    sys.stdout.write("\033[31mLoading...\r")
    sys.stdout.flush()
    time.sleep(0.5)
    sys.stdout.write("\033[32mComplete! \033[0m\n")
    sys.stdout.flush()
    
    print("\n=== Test Complete ===\n")


if __name__ == "__main__":
    demo_ansi_colors()
