#!/usr/bin/env python3
"""Simple File Crypter - Main entry point"""

import sys

from cli.cli import app, start_interactive_mode


def main():
    if len(sys.argv) == 1:
        start_interactive_mode()
    else:
        app()

if __name__ == "__main__":
    main()