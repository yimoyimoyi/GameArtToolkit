# -*- coding: utf-8 -*-
import sys
import traceback
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
APP_DIR = BASE_DIR / "app"
sys.path.insert(0, str(APP_DIR))

def log(s):
    print(s, flush=True)

from PySide6.QtWidgets import QApplication

def run_debug():
    log("[1] Creating QApplication")
    app = QApplication(sys.argv)
    log("[2] Importing MainWindow")
    from pyside_app import MainWindow
    log("[3] Instantiating MainWindow")
    main_win = MainWindow()
    log("[4] MainWindow instantiated!")
    main_win.show()
    log("[5] MainWindow shown!")

if __name__ == "__main__":
    try:
        run_debug()
        log("[6] Exiting debug cleanly")
    except Exception:
        traceback.print_exc()
