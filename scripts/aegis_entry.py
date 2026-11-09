"""PyInstaller entry point (convenience binaries only).

The canonical release artifact is the attested, reproducible
source zip; these binaries exist so a reviewer can run the
engine without a Python install. freeze_support() is required
before anything else: parscan uses multiprocessing, and a
frozen executable without it respawns itself as a worker in a
loop.
"""
import multiprocessing
import sys

multiprocessing.freeze_support()

from aegis.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
