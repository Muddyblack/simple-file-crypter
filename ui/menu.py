"""
Menu components for FileCrypter application.
These components create navigation menus and structured UI elements.
"""

from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from . import console

def display_menu_header(title, parent=None, grand_parent=None):
    """Display a menu title with navigation breadcrumbs"""
    # Build breadcrumb trail
    breadcrumb_parts = []
    if grand_parent:
        breadcrumb_parts.append(f"[blue]{grand_parent}[/blue]")
    if parent:
        breadcrumb_parts.append(f"[cyan]{parent}[/cyan]")
    if title:
        breadcrumb_parts.append(f"[green]{title}[/green]")
    
    breadcrumb = " > ".join(breadcrumb_parts)
    
    # Create a panel with the breadcrumb
    if breadcrumb:
        panel = Panel(breadcrumb, expand=False)
        console.print(panel)


def display_menu(options, title="Menu", parent=None, grand_parent=None, show_shortcuts=False):
    """
    Display a menu with options and return a Rich Table object
    
    Args:
        options: List of tuples (shortcut, description, function)
        title: Menu title
        parent: Parent menu title for breadcrumbs
        grand_parent: Grand parent menu title for breadcrumbs
        show_shortcuts: Whether to show keyboard shortcuts (default: False)
        
    Returns:
        Rich Table object
    """
    # Display the header/breadcrumbs first
    display_menu_header(title, parent, grand_parent)
    
    # Create table for options
    table = Table(show_header=False, box=None, padding=(0, 1, 0, 0))
    table.add_column("Shortcut", style="cyan", no_wrap=True)
    table.add_column("Description", style="white")
    
    # Add options to table - simplified without shortcuts
    for option in options:
        shortcut, description = option[0], option[1]
        table.add_row(shortcut, description)
    
    return table


def display_quick_menu(title, options):
    """
    Display a simplified menu that immediately returns user selection
    
    Args:
        title: Menu title
        options: List of (value, description) tuples
        
    Returns:
        Selected value or None if cancelled
    """
    from rich.prompt import Prompt
    
    console.print(f"[blue]{title}[/blue]")
    
    # Display options
    for i, (value, description) in enumerate(options, 1):
        console.print(f"[cyan]{i}.[/cyan] {description}")
    
    # Add cancel option
    console.print(f"[cyan]0.[/cyan] Cancel")
    
    # Get user input
    try:
        choice = Prompt.ask("\nEnter your choice", default="0")
        
        # Handle direct selection by number
        if choice.isdigit():
            idx = int(choice)
            if idx == 0:
                return None
            if 1 <= idx <= len(options):
                return options[idx-1][0]
        
        # Check if user entered an option value directly
        for value, _ in options:
            if choice.lower() == str(value).lower():
                return value
                
        return None
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled.[/yellow]")
        return None
