# -*- mode: python ; coding: utf-8 -*-
#
# Tcl/Tk 注意事項（conda 環境）：
# PyInstaller 依 PATH 搜尋 tcl86t.dll / tk86t.dll。若 PATH 先碰到 base anaconda 的 Library\bin，
# 就會把 base 的 DLL（例如 8.6.15）和本環境的 Tcl 腳本（init.tcl 要求 -exact 8.6.13）混包，
# exe 開 GUI 時報 "version conflict for package Tcl: have 8.6.15, need exactly 8.6.13"。
# 這裡強制從建置用 python 所在環境（sys.prefix\Library\bin）取 DLL，並把該夾插到 PATH 最前，
# 不受外部 PATH 影響。驗證：scripts/instance_test.py --mode exe。
import os
import sys

_env_bin = os.path.join(sys.prefix, "Library", "bin")
_tcltk_dlls = [
    (os.path.join(_env_bin, name), ".")
    for name in ("tcl86t.dll", "tk86t.dll")
    if os.path.exists(os.path.join(_env_bin, name))
]
os.environ["PATH"] = _env_bin + os.pathsep + os.environ.get("PATH", "")


a = Analysis(
    ['src\\main.py'],
    pathex=['.'],
    binaries=_tcltk_dlls,
    datas=[],
    hiddenimports=[],
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
    a.binaries,
    a.datas,
    [],
    name='IDMasker',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
