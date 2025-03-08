import os
from typing import Optional

import typer
from rich.console import Console
from rich.prompt import Confirm, Prompt

from ui.file_dialog import open_directory_dialog, open_file_dialog, open_save_dialog
from ui.file_display import display_selected_directory, display_selected_file
from utils.path_cleaner import clean_path

console = Console()

def get_file_path(prompt_text: str, for_saving: bool = False, must_exist: bool = True) -> Optional[str]:
    """
    Get a file path from the user with support for file dialog
    
    Args:
        prompt_text: The prompt text to show
        for_saving: Whether this is for saving a file
        must_exist: Whether the file must exist
        
    Returns:
        The selected file path or None if canceled
    """
    file_path = typer.prompt(f"{prompt_text} (or -e/-ef for file explorer, 'back' to return)")
    
    if file_path.lower() == 'back':
        return None
        
    # Check if user wants to use file explorer
    if file_path.lower() in ['-e', '-ef', '--explorer']:
        if for_saving:
            file_path = open_save_dialog(prompt_text)
        else:
            file_path = open_file_dialog(prompt_text)
            
        if not file_path:  # User canceled the dialog
            console.print("[yellow]File selection canceled.[/yellow]")
            return None
            
        display_selected_file(file_path)
    else:
        file_path = clean_path(file_path)
        
        if must_exist and not os.path.isfile(file_path):
            console.print(f"[red]Invalid file path: '{file_path}'[/red]")
            return None
            
        if not for_saving:  # Only display for existing files
            display_selected_file(file_path)
    
    return file_path

def get_directory_path(prompt_text: str, must_exist: bool = True) -> Optional[str]:
    """
    Get a directory path from the user with support for directory dialog
    
    Args:
        prompt_text: The prompt text to show
        must_exist: Whether the directory must exist
        
    Returns:
        The selected directory path or None if canceled
    """
    dir_path = typer.prompt(f"{prompt_text} (or -e/-ed for directory explorer, 'back' to return)")
    
    if dir_path.lower() == 'back':
        return None
        
    # Check if user wants to use directory explorer
    if dir_path.lower() in ['-e', '-ed', '--explorer']:
        dir_path = open_directory_dialog(prompt_text)
        if not dir_path:  # User canceled the dialog
            console.print("[yellow]Directory selection canceled.[/yellow]")
            return None
            
        display_selected_directory(dir_path)
    else:
        dir_path = clean_path(dir_path)
        
        if must_exist and not os.path.isdir(dir_path):
            console.print(f"[red]Invalid directory path: '{dir_path}'[/red]")
            return None
            
        display_selected_directory(dir_path)
    
    return dir_path

def get_password(confirm: bool = False, allow_empty: bool = True) -> Optional[str]:
    """
    Get a password from the user with optional confirmationn
    
    Args:
        confirm: Whether to ask for password confirmation
        allow_empty: Whether to allow empty passwords (default: True)
        
    Returns:
        The password or None if passwords don't match
    """
    password = Prompt.ask("Enter password", password=True)
    
    # Check for empty password only if not allowed
    if not allow_empty and password == "":
        console.print("[bold red]Empty password not allowed.[/bold red]")
        return None
    
    if confirm:
        confirm_password = Prompt.ask("Confirm password", password=True)
        if password != confirm_password:
            console.print("[bold red]Passwords don't match![/bold red]")
            return None
    
    return password

def get_output_path(input_path: str, default_extension: str = ".sfc") -> Optional[str]:
    """
    Get an output path for saving a file
    
    Args:
        input_path: The input file path
        default_extension: The default extension to use
        
    Returns:
        The output path or None if canceled
    """
    default_output = f"{input_path}{default_extension}"
    use_default = Confirm.ask(f"Save as '{default_output}'? [Enter=Yes]", default=True)
    
    if use_default:
        return default_output
        
    output_path_input = typer.prompt("Enter output path (or -e for explorer)")
    
    # Check if user wants to use file explorer for output path
    if output_path_input.lower() in ['-e', '--explorer']:
        output_path = open_save_dialog("Save file as")
        
        if not output_path:  # User canceled the dialog
            console.print("[yellow]Output file selection canceled. Using default path.[/yellow]")
            return default_output
            
        # Make sure the file has the expected extension
        if default_extension and not output_path.lower().endswith(default_extension.lower()):
            output_path += default_extension
    else:
        output_path = output_path_input.strip().strip("'").strip('"')
        
    return output_path
