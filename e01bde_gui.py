#!/usr/bin/env python3
"""Atalho para abrir a interface grafica:  python e01bde_gui.py"""
import multiprocessing

from e01bde.gui import main

if __name__ == "__main__":
    multiprocessing.freeze_support()  # necessario para o .exe (PyInstaller)
    main()
