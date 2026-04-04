# -*- mode: python ; coding: utf-8 -*-
import sys

# Determine the correct icon and executable name based on platform
if sys.platform == 'darwin':
    icon_file = 'icon.icns'
    exe_name = 'ESP-Flasher'
elif sys.platform == 'win32':
    icon_file = 'icon.ico'
    exe_name = 'ESP-Flasher.exe'
else:
    icon_file = None
    exe_name = 'ESP-Flasher'


a = Analysis(
    ['esp_flasher/__main__.py'],
    pathex=[],
    binaries=[],
    datas=[('esp_flasher/stubs/*.json', 'esp_flasher/stubs')],
    hiddenimports=['colorama'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name=exe_name,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_file,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='ESP-Flasher',
)

# Only create macOS app bundle on macOS
if sys.platform == 'darwin':
    app = BUNDLE(
        coll,
        name='ESP-Flasher.app',
        icon='icon.icns',
        bundle_identifier=None,
    )
