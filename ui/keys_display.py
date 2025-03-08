"""
UI display components for FileCrypter application.
These functions are responsible for rendering structured information in the terminal.
"""

from rich import box
from rich.panel import Panel
from rich.table import Table

from . import console
from .icons import get_key_status_icon


# Key visualization helpers
def display_key_table(keys, key_type, title, columns=("Filename", "Path")):
    """
    Display keys in a formatted table.
    
    Args:
        keys: List of key dictionaries
        key_type: Type of keys (private, public, trusted, revoked)
        title: Table title
        columns: Column headers
    """
    if not keys:
        console.print(f"\n[yellow]No {key_type} keys found[/yellow]")
        return
        
    console.print(f"\n[blue]{title}:[/blue]")
    table = Table(show_header=True, header_style="blue", box=box.SIMPLE)
    
    # Add columns
    for column in columns:
        table.add_column(column)
    
    # Add rows based on key type
    if key_type == "trusted":
        # Special handling for trusted keys with fingerprint
        for key in keys:
            fingerprint = key.get("fingerprint", "unknown")
            table.add_row(key['alias'], fingerprint, key['path'])
    else:
        # Standard handling for other key types
        for key in keys:
            if len(columns) == 2:
                table.add_row(key['filename'], key['path'])
            
    console.print(table)

def display_all_keys_as_tables(keys_dict):
    """
    Display all keys using formatted tables.
    
    Args:
        keys_dict: Dictionary containing different key types
    """
    console.print("[bold blue]Available Keys[/bold blue]")
    
    # Display private keys
    if keys_dict["private"]:
        display_key_table(keys_dict["private"], "private", "Private Keys")
    else:
        console.print("\n[yellow]No private keys found[/yellow]")
    
    # Display public keys
    if keys_dict["public"]:
        display_key_table(keys_dict["public"], "public", "Public Keys")
    else:
        console.print("\n[yellow]No public keys found[/yellow]")
    
    # Display trusted keys with additional fingerprint column
    if keys_dict["trusted"]:
        display_key_table(
            keys_dict["trusted"], 
            "trusted", 
            "Trusted Keys", 
            columns=("Alias", "Fingerprint", "Path")
        )
    else:
        console.print("\n[yellow]No trusted keys found[/yellow]")
    
    # Display revoked keys
    if keys_dict["revoked"]:
        display_key_table(keys_dict["revoked"], "revoked", "Revoked Keys")
    else:
        console.print("\n[yellow]No revoked keys found[/yellow]")

def display_key_panel(key, key_type="trusted"):
    """
    Display a key's details in a formatted panel with icons.
    
    Args:
        key: Dictionary containing key information
        key_type: Type of key (private, public, trusted, revoked)
    """
    icon = get_key_status_icon(key_type)
    title = f"[bold green]{icon} {key_type.capitalize()} Key[/bold green]"
    
    if key_type == "trusted":
        fingerprint = key.get("fingerprint", "unknown")
        key_info = f"[bold]{key['alias']}[/bold]\n"
        key_info += f"Fingerprint: {fingerprint}\n"
        key_info += f"Path: {key['path']}"
    else:
        key_info = f"[bold]{key.get('filename', 'Unknown')}[/bold]\n"
        key_info += f"Path: {key['path']}"
    
    border_style = {
        "private": "purple",
        "public": "blue",
        "trusted": "green",
        "revoked": "red"
    }.get(key_type, "blue")
    
    console.print(Panel(
        key_info,
        title=title,
        border_style=border_style,
        box=box.ROUNDED
    ))

def display_keys_as_panels(keys_dict):
    """
    Display all keys using panels with icons.
    
    Args:
        keys_dict: Dictionary containing different key types
    """
    console.print("[bold blue]Available Keys[/bold blue]")
    
    # Display private keys
    console.print("\n[blue]Private Keys:[/blue]")
    if keys_dict["private"]:
        for key in keys_dict["private"]:
            display_key_panel(key, "private")
    else:
        console.print("[yellow]No private keys found[/yellow]")
    
    # Display public keys
    console.print("\n[blue]Public Keys:[/blue]")
    if keys_dict["public"]:
        for key in keys_dict["public"]:
            display_key_panel(key, "public")
    else:
        console.print("[yellow]No public keys found[/yellow]")
    
    # Display trusted keys
    console.print("\n[blue]Trusted Keys:[/blue]")
    if keys_dict["trusted"]:
        for key in keys_dict["trusted"]:
            display_key_panel(key, "trusted")
    else:
        console.print("[yellow]No trusted keys found[/yellow]")
    
    # Display revoked keys
    console.print("\n[blue]Revoked Keys:[/blue]")
    if keys_dict["revoked"]:
        for key in keys_dict["revoked"]:
            display_key_panel(key, "revoked")
    else:
        console.print("[yellow]No revoked keys found[/yellow]")
