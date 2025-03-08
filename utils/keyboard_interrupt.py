from click.exceptions import Abort
from rich.console import Console

console = Console()

def handle_keyboard_interrupt(func):
    """Decorator to handle keyboard interrupts gracefully"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (KeyboardInterrupt, Abort): 
            console.print("\n[yellow]Operation cancelled. Returning to menu...[/yellow]")
            return None
    return wrapper
