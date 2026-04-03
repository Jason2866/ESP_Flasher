# Build Instructions

Instructions for building standalone ESP-Flasher binaries using [PyInstaller](https://pyinstaller.org/).

## Prerequisites (all platforms)

- Python >= 3.9 (CI uses 3.13)
- Clone or download the repository:
  ```bash
  git clone https://github.com/Jason2866/ESP_Flasher.git
  cd ESP_Flasher
  ```
- Install all dependencies:
  ```bash
  pip install -r requirements.txt -r requirements_build.txt
  pip install -e .
  ```
- Verify the installation:
  ```bash
  esp_flasher -h
  ```

---

## Windows

1. Install Python >= 3.9 from [python.org](https://www.python.org/downloads/) (make sure to check "Add to PATH")
2. Open a terminal in the project directory
3. Install dependencies (see [Prerequisites](#prerequisites-all-platforms))
4. Build the binary:
   ```bash
   python -m PyInstaller.__main__ -w -n ESP-Flasher -i icon.ico --add-data "esp_flasher/stubs/*.json;esp_flasher/stubs" esp_flasher\__main__.py
   ```
5. Verify the binary:
   ```bash
   dist\ESP-Flasher\ESP-Flasher.exe -h
   ```

The output is `dist\ESP-Flasher\` (a directory containing the executable and all dependencies).

---

## macOS (Intel)

1. Install Python >= 3.9
2. Install dependencies (see [Prerequisites](#prerequisites-all-platforms))
3. Build the binary:
   ```bash
   .venv/bin/pyinstaller -w -n ESP-Flasher -i icon.icns --add-data "esp_flasher/stubs/*.json:esp_flasher/stubs" esp_flasher/__main__.py
   ```
4. Verify the binary:
   ```bash
   dist/ESP-Flasher/ESP-Flasher -h
   ```

The output is `dist/ESP-Flasher.app` (an app bundle using the onedir layout for fast startup).

---

## macOS (ARM / Apple Silicon)

Same steps as macOS Intel — PyInstaller builds for the native architecture automatically.

### Using a virtual environment (recommended)

1. Open your IDE (e.g. VS Code) and create a virtual environment
2. Activate it and install all dependencies (see [Prerequisites](#prerequisites-all-platforms))
3. Build the binary using the venv's PyInstaller:
   ```bash
   .venv/bin/pyinstaller -w -n ESP-Flasher -i icon.icns --add-data "esp_flasher/stubs/*.json:esp_flasher/stubs" esp_flasher/__main__.py
   ```

The output is `dist/ESP-Flasher.app`.

---

## Linux (Ubuntu / Debian)

1. Install Python >= 3.9 and required system libraries:
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip libnotify-dev libsdl2-dev
   ```
2. Install dependencies (see [Prerequisites](#prerequisites-all-platforms))
3. Build the binary:
   ```bash
   python -m PyInstaller.__main__ -w -n ESP-Flasher -i icon.ico --add-data "esp_flasher/stubs/*.json:esp_flasher/stubs" esp_flasher/__main__.py
   ```
4. Verify the binary:
   ```bash
   dist/ESP-Flasher/ESP-Flasher -h
   ```

The output is `dist/ESP-Flasher/` (a directory containing the executable and all dependencies).

> **Note:** On Linux, your user needs serial port access. Run once:
> ```bash
> sudo usermod -a -G dialout $(whoami)
> ```
> Then log out and back in.

---

## Output summary

| Platform | Output |
|----------|--------|
| Windows | `dist\ESP-Flasher\` (directory with `ESP-Flasher.exe`) |
| macOS (Intel) | `dist/ESP-Flasher.app` (onedir bundle) |
| macOS (ARM) | `dist/ESP-Flasher.app` (onedir bundle) |
| Linux | `dist/ESP-Flasher/` (directory with `ESP-Flasher`) |
