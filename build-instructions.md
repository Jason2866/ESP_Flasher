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

## Quick Build (Recommended)

The easiest way to build the application is using the provided spec file, which automatically handles platform-specific settings (icons, file extensions, etc.):

```bash
pyinstaller ESP-Flasher.spec
```

This works on all platforms (Windows, macOS, Linux) and produces the appropriate output:
- **Windows**: `dist\ESP-Flasher\ESP-Flasher.exe`
- **macOS**: `dist/ESP-Flasher.app`
- **Linux**: `dist/ESP-Flasher/ESP-Flasher`

---

## Platform-Specific Instructions

### Windows

**Option 1: Using the spec file (recommended)**
1. Install Python >= 3.9 from [python.org](https://www.python.org/downloads/) (make sure to check "Add to PATH")
2. Open a terminal in the project directory
3. Install dependencies (see [Prerequisites](#prerequisites-all-platforms))
4. Build the binary:
   ```bash
   pyinstaller ESP-Flasher.spec
   ```
5. Verify the binary:
   ```bash
   dist\ESP-Flasher\ESP-Flasher.exe -h
   ```

**Option 2: Manual PyInstaller command**
```bash
python -m PyInstaller.__main__ -w -n ESP-Flasher.exe -i icon.ico --add-data "esp_flasher/stubs/*.json;esp_flasher/stubs" esp_flasher\__main__.py
```

The output is `dist\ESP-Flasher\` (a directory containing the executable and all dependencies).

---

### macOS (Intel & Apple Silicon)

**Option 1: Using the spec file (recommended)**
1. Install Python >= 3.9
2. Install dependencies (see [Prerequisites](#prerequisites-all-platforms))
3. Build the binary:
   ```bash
   pyinstaller ESP-Flasher.spec
   ```
4. Verify the binary:
   ```bash
   dist/ESP-Flasher.app/Contents/MacOS/ESP-Flasher -h
   ```

**Option 2: Manual PyInstaller command**
```bash
pyinstaller -w -n ESP-Flasher -i icon.icns --add-data "esp_flasher/stubs/*.json:esp_flasher/stubs" esp_flasher/__main__.py
```

The output is `dist/ESP-Flasher.app` (an app bundle using the onedir layout for fast startup).

PyInstaller builds for the native architecture automatically (Intel or ARM).

#### Using a virtual environment (recommended)

1. Open your IDE (e.g. VS Code) and create a virtual environment
2. Activate it and install all dependencies (see [Prerequisites](#prerequisites-all-platforms))
3. Build the binary using the venv's PyInstaller:
   ```bash
   .venv/bin/pyinstaller ESP-Flasher.spec
   ```

---

### Linux (Ubuntu / Debian)

**Option 1: Using the spec file (recommended)**
1. Install Python >= 3.9 and required system libraries:
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip libnotify-dev libsdl2-dev
   ```
2. Install dependencies (see [Prerequisites](#prerequisites-all-platforms))
3. Build the binary:
   ```bash
   pyinstaller ESP-Flasher.spec
   ```
4. Verify the binary:
   ```bash
   dist/ESP-Flasher/ESP-Flasher -h
   ```

**Option 2: Manual PyInstaller command**
```bash
python -m PyInstaller.__main__ -w -n ESP-Flasher -i icon.ico --add-data "esp_flasher/stubs/*.json:esp_flasher/stubs" esp_flasher/__main__.py
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
| Windows | `dist\ESP-Flasher\ESP-Flasher.exe` |
| macOS (Intel) | `dist/ESP-Flasher.app` (onedir bundle) |
| macOS (ARM) | `dist/ESP-Flasher.app` (onedir bundle) |
| Linux | `dist/ESP-Flasher/ESP-Flasher` |

---

## Spec File Benefits

Using `ESP-Flasher.spec` provides several advantages:
- **Automatic platform detection**: Correct icon format and file extension for each OS
- **Consistent builds**: Same command works on all platforms
- **Maintainability**: Single source of truth for build configuration
- **macOS app bundle**: Only created on macOS (not on Windows/Linux)
