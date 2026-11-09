# PyInstaller spec for the convenience binaries. The canonical
# release artifact remains the attested reproducible source zip.
import os

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))

a = Analysis(
    [os.path.join(ROOT, "scripts", "aegis_entry.py")],
    pathex=[ROOT],
    binaries=[],
    datas=[
        (os.path.join(ROOT, "rules"), "rules"),
        (os.path.join(ROOT, "sigma_json"), "sigma_json"),
        (os.path.join(ROOT, "yara_rules"), "yara_rules"),
    ],
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="aegis",
          console=True)
coll = COLLECT(exe, a.binaries, a.datas, name="aegis")
