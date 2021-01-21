# macOS

`pyinstaller -F -w -n ESP-Flasher -i icon.icns esp_flasher/__main__.py`

# Windows

1. Start up VM
2. Install Python (3) from App Store
3. Download esp-flasher from GitHub
4. `pip install -e.` and `pip install pyinstaller`
5. Check with `python -m esp_flasher.__main__`
6. `python -m PyInstaller.__main__ -F -w -n ESP-Flasher -i icon.ico esp_flasher\__main__.py`
7. Go to `dist` folder, check ESP-Flasher.exe works.
