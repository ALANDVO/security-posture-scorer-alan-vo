#!/usr/bin/env python3
"""Unified entrypoint forwarding to modular backend implementation."""
import sys
import os

# Ensure backend package is in python search path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.app.main import app, cli_main

if __name__ == "__main__":
    cli_main()
