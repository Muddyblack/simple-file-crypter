"""Utilities for intelligently detecting file and directory paths"""
import json
import mimetypes
import os
from typing import Literal, Optional, Tuple

# Initialize mimetypes
mimetypes.init()

def detect_path_type(path: str) -> Literal["file", "directory", "unknown"]:
    """
    Detect if a path is a file, directory, or unknown
    
    Args:
        path: The path to check
        
    Returns:
        String indicating the path type: "file", "directory", or "unknown"
    """
    # First check if path exists
    if os.path.exists(path):
        if os.path.isdir(path):
            return "directory"
        elif os.path.isfile(path):
            return "file"
    
    # Path doesn't exist, try to infer from other clues
    # If it ends with a path separator, it's likely a directory
    if path.endswith(os.sep):
        return "directory"
    
    # Check if it has a file extension that we recognize
    _, ext = os.path.splitext(path)
    if ext:
        # If it has a recognized extension, it's probably a file
        if mimetypes.types_map.get(ext.lower()):
            return "file"
    
    # If we get here, we're not sure
    return "unknown"

def is_encrypted_file(path: str) -> bool:
    """
    Check if a file appears to be encrypted based on extension or content
    
    Args:
        path: The path to check
        
    Returns:
        True if the file appears to be encrypted, False otherwise
    """
    # First check if it's a directory archive - if it is, we return False
    if is_encrypted_directory_archive(path):
        return False
        
    try:
        if not os.path.isfile(path):
            return False
        
        # Check if it has our extension
        if not path.lower().endswith('.sfc'):
            return False
            
        # Check minimum file size
        if os.path.getsize(path) < 100:
            return False
        
        with open(path, 'rb') as f:
            # Read metadata length (4 bytes)
            metadata_length_bytes = f.read(4)
            if len(metadata_length_bytes) != 4:
                return False
                
            metadata_length = int.from_bytes(metadata_length_bytes, 'big')
            
            # Sanity check on metadata length
            if metadata_length <= 0 or metadata_length > 10000:
                return False
                
            # Try to parse the metadata
            metadata_bytes = f.read(metadata_length)
            metadata = json.loads(metadata_bytes.decode('utf-8'))
            
            # Check for required metadata fields
            if "version" not in metadata:
                return False

            # If it has directory content type, it's not a regular file
            if metadata.get("content_type") == "directory":
                return False
                
            # Must have either public key or password encryption fields
            if metadata.get("encryption_method") == "public_key":
                return "encrypted_key" in metadata and "recipient" in metadata
            else:
                return "salt" in metadata and "nonce" in metadata
            
    except Exception:
        return False

def is_public_key_encrypted_file(file_path: str) -> bool:
    """
    Check if a file was encrypted with a public key
    
    Args:
        file_path: Path to the file
        
    Returns:
        True if encrypted with public key, False otherwise
    """
    try:
        if not os.path.isfile(file_path):
            return False
            
        with open(file_path, 'rb') as f:
            # Read metadata length (4 bytes)
            metadata_length_bytes = f.read(4)
            metadata_length = int.from_bytes(metadata_length_bytes, 'big')
            
            # Try to parse the metadata
            metadata_bytes = f.read(metadata_length)
            metadata = json.loads(metadata_bytes.decode('utf-8'))
            
            # Check encryption method
            return metadata.get("encryption_method") == "public_key"
    except Exception:
        return False

def is_encrypted_directory_archive(path: str) -> bool:
    """
    Check if a file appears to be an encrypted directory archive
    
    Args:
        path: The path to check
        
    Returns:
        True if the file appears to be an encrypted directory archive, False otherwise
    """
    if not os.path.isfile(path):
        return False

    try:
        with open(path, 'rb') as f:
            # Read metadata length (4 bytes)
            metadata_length_bytes = f.read(4)
            if len(metadata_length_bytes) != 4:
                return False
                
            metadata_length = int.from_bytes(metadata_length_bytes, 'big')
            
            # Sanity check on metadata length
            if metadata_length <= 0 or metadata_length > 10000:
                return False
                
            # Try to parse the metadata
            metadata_bytes = f.read(metadata_length)
            metadata = json.loads(metadata_bytes.decode('utf-8'))
            
            # Check specifically for directory content type AND encryption method
            return (metadata.get("content_type") == "directory" and 
                   ("encryption_method" in metadata) and
                   any(key in metadata for key in ["salt", "nonce", "encrypted_key"]))
            
    except Exception:
        return False

def get_smart_path(prompt_text: str, for_saving: bool = False) -> Tuple[Optional[str], Optional[str]]:
    """
    Get a path from the user and intelligently determine if it's a file or directory
    
    Args:
        prompt_text: The prompt to show to the user
        for_saving: Whether the path is for saving (affects validation)
        
    Returns:
        Tuple of (path, type) where type is "file", "directory", or None if canceled
    """
    from utils.input_handlers import get_directory_path, get_file_path
    from ui.file_dialog import open_directory_dialog, open_file_dialog
    from ui.file_display import display_selected_directory, display_selected_file
    
    path = None
    path_type = None
    
    # Use a more general prompt since we don't know if it's a file or directory yet
    display_prompt = f"{prompt_text} (path, -ef for file explorer, -ed for directory explorer, 'back' to return)"
    
    # First attempt without requiring existence, so we can check what type it is
    from rich.prompt import Prompt
    path_input = Prompt.ask(display_prompt)
    
    if path_input.lower() == 'back':
        return None, None

    # Check if user wants to use specific explorer type directly
    if path_input.lower() == '-ef':
        # User directly requested file explorer - open it immediately
        from rich.console import Console
        console = Console()
        path = open_file_dialog("Select file")
        if not path:
            console.print("[yellow]File selection canceled.[/yellow]")
            return None, None
        path_type = "file"
        display_selected_file(path)
        return path, path_type
    
    elif path_input.lower() == '-ed':
        # User directly requested directory explorer - open it immediately
        from rich.console import Console
        console = Console()
        path = open_directory_dialog("Select directory")
        if not path:
            console.print("[yellow]Directory selection canceled.[/yellow]")
            return None, None
        path_type = "directory"
        display_selected_directory(path)
        return path, path_type
    
    # Check if user wants to use explorer
    if path_input.lower() in ['-e', '--explorer']:
        # Ask user what type they want to select
        from rich.prompt import Confirm
        is_file = Confirm.ask("Select a file? [Enter=Yes, n=Select directory]", default=True)
        
        if is_file:
            path = get_file_path("Select file", for_saving=for_saving, must_exist=not for_saving)
            path_type = "file" if path else None
        else:
            path = get_directory_path("Select directory", must_exist=not for_saving)
            path_type = "directory" if path else None
    else:
        # Clean up the path
        from utils.path_cleaner import clean_path
        path = clean_path(path_input)
        
        # Detect path type
        path_type = detect_path_type(path)
        
        # If we couldn't detect reliably, ask the user
        if path_type == "unknown":
            from rich.prompt import Confirm
            is_file = Confirm.ask(f"Is '{path}' a file? [Enter=Yes, n=Directory]", default=True)
            path_type = "file" if is_file else "directory"
        
        # Display information about the selected path
        if path_type == "file" and os.path.exists(path):
            display_selected_file(path)
        elif path_type == "directory" and os.path.exists(path):
            display_selected_directory(path)
    
    return path, path_type
