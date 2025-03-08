"""
UI package for FileCrypter application.
This package provides UI components and helper functions for the FileCrypter application.
"""

from rich.console import Console

# Create a shared console instance that can be imported throughout the application
console = Console()

# Import and expose key functions from the submodules
from .keys_display import display_all_keys_as_tables, display_key_panel, display_key_table, display_keys_as_panels # noqa
from .icons import get_key_status_icon, get_operation_status_icon # noqa
from .menu import display_menu, display_menu_header # noqa
from .progress import create_progress_indicator, show_processing_animation, with_progress # noqa

__all__ = [
    'console',
    'display_key_table',
    'display_all_keys_as_tables',
    'display_key_panel',
    'display_keys_as_panels',
    'create_progress_indicator',
    'with_progress',
    'show_processing_animation',
    'display_menu_header',
    'display_menu',
    'get_key_status_icon',
    'get_operation_status_icon'
]
