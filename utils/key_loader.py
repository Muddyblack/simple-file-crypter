import time
from typing import Optional, Tuple

from rich.console import Console

console = Console()

def load_default_keys(crypto) -> Tuple[Optional[bytes], Optional[bytes]]:
    """Load or generate default keys with nice UI feedback"""
    with console.status("[bold green]Loading encryption keys...[/bold green]"):
        time.sleep(0.5)  # Small delay for UX
        try:
            private_key, public_key = crypto.get_default_keypair()
            console.print(f"[green]✓[/green] Using keys from: [bold]{crypto.keys_dir}[/bold]", justify="center")
            return private_key, public_key
        except Exception as e:
            console.print(f"[yellow]![/yellow] Key loading error: {e}")
            console.print("[yellow]![/yellow] Will generate new keys when needed")
            return None, None
