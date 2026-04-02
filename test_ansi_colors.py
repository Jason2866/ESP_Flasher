#!/usr/bin/env python3
"""
Test script to demonstrate ANSI color support in ESP-Flasher
"""

def test_ansi_colors():
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
    
    print("\n=== Test Complete ===\n")


if __name__ == "__main__":
    test_ansi_colors()
