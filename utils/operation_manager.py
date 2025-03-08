"""Unified operation management for CLI and interactive modes"""
import json
import os
import re
from typing import Callable, Optional, Tuple

from rich.console import Console
from rich.prompt import Confirm, Prompt
import typer

from core.keys import KeyManager
from ui.file_dialog import open_save_dialog
from utils.input_handlers import get_directory_path, get_file_path, get_output_path, get_password
from utils.path_detector import is_encrypted_directory_archive
from utils.progress_handler import execute_with_progress

console = Console()

def handle_file_encryption(
    crypto_func: Callable, 
    file_path: str, 
    password: Optional[str] = None,
    output: Optional[str] = None,
    interactive: bool = False
) -> Tuple[bool, Optional[str]]:
    """
    Handle file encryption with consistent behavior across CLI and interactive modes
    
    Args:
        crypto_func: Encryption function to call
        file_path: Path to the file to encrypt
        password: Optional password (will prompt if None)
        output: Optional output path (will use default if None)
        interactive: Whether this is in interactive mode
        
    Returns:
        Tuple of (success, error_message)
    """
    # Get filename for display
    filename = os.path.basename(file_path)
    
    # Ask for encryption method
    use_public_key = False
    if interactive:
        console.print("\n[blue]Choose encryption method:[/blue]")
        console.print("1. Password (symmetric encryption)")
        console.print("2. Public key (encrypt for someone else)")
        choice = Prompt.ask("Select option", choices=["1", "2"], default="1")
        use_public_key = choice == "2"
    
    # Determine output path
    if not output:
        if interactive:
            output = get_output_path(file_path)
            if not output:
                return False, "Output path selection canceled"
        else:
            output = f"{file_path}.sfc"
    
    # Handle public key encryption
    if use_public_key:
        # Get key manager
        key_manager = KeyManager()
        trusted_keys = key_manager.get_trusted_keys()
        
        if not trusted_keys:
            console.print("\n[bold yellow]No trusted public keys found![/bold yellow]")
            console.print("[yellow]You need to import a public key first.[/yellow]")
            
            if interactive and Confirm.ask("Would you like to import a public key now?", default=True):
                # Show instructions for importing a key
                console.print("\n[blue]To import a public key:[/blue]")
                console.print("1. Go to Key Management menu")
                console.print("2. Select 'Import public key'")
                console.print("3. Follow the prompts to import a key\n")
                
                if Confirm.ask("Continue with password encryption instead?", default=True):
                    # Fall back to password encryption
                    use_public_key = False
                else:
                    return False, "No trusted keys available"
            else:
                return False, "No trusted keys available"
        
    # Get encryption parameters
    trusted_key = None
    
    if use_public_key:
        # Show available trusted keys
        console.print("\n[blue]Available trusted keys:[/blue]")
        keys_list = []
        for idx, (alias, info) in enumerate(trusted_keys.items(), 1):
            fingerprint = info.get("fingerprint", "unknown")
            console.print(f"{idx}. {alias} ({fingerprint})")
            keys_list.append((alias, info))
        
        # Select key
        key_idx = int(Prompt.ask(
            "Select key number", 
            choices=[str(i) for i in range(1, len(keys_list) + 1)],
            default="1"
        ))
        
        alias, trusted_key = keys_list[key_idx - 1]
        console.print(f"[blue]Using key:[/blue] {alias}")
    else:
        # Get password if not provided - allow empty passwords
        if password is None:  # Check if None, not if falsy (empty strings are valid)
            password = get_password(confirm=True, allow_empty=True)
            if password is None:  # Only None means error, "" is valid
                return False, "Password confirmation failed"
    
    # Show what we're about to do
    console.print(f"\n[bold]Encrypting:[/bold] {filename}")
    console.print(f"[bold]Output:[/bold] {output}")
    console.print(f"[bold]Method:[/bold] {'Public key' if use_public_key else 'Password'}")
    
    try:
        # Encrypt with progress
        if use_public_key:
            if trusted_key is None:
                console.print("[red]Error: No trusted key selected[/red]")
                return False, "No trusted key selected"
                
            execute_with_progress(
                crypto_func,
                (file_path, output, None, trusted_key),
                task_description="Encrypting...",
            )
        else:
            # Ensure password is not None, use empty string as fallback
            password = "" if password is None else password
            
            execute_with_progress(
                crypto_func,
                (file_path, output, password, None),
                task_description="Encrypting...",
            )
        
        
        console.print("\n[bold green]✓ File encrypted successfully![bold green]")
        
        # Show file info
        file_size = os.path.getsize(output)
        console.print(f"[dim]Encrypted file size: {file_size/1024:.1f} KB[/dim]")
        
        return True, None
            
    except Exception as e:
        console.print("\n[bold red]✗ Encryption failed![bold red]")
        console.print(f"[red]Error: {str(e)}[/red]")
        return False, str(e)

def handle_file_decryption(
    crypto_func: Callable, 
    file_path: str, 
    password: Optional[str] = None,
    output: Optional[str] = None,
    interactive: bool = False
) -> Tuple[bool, Optional[str]]:
    """
    Handle file decryption with consistent behavior across CLI and interactive modes
    
    Args:
        crypto_func: Decryption function to call
        file_path: Path to the file to decrypt
        password: Optional password (will prompt if None)
        output: Optional output path (will use default if None)
        interactive: Whether this is in interactive mode
        
    Returns:
        Tuple of (success, error_message)
    """
    # Get filename for display
    filename = os.path.basename(file_path)
    
    # Check for signature and verify if exists
    if interactive:
        should_proceed = check_and_verify_signature_before_decryption(
            crypto_func.__self__,  # The SecureFileCrypto object
            file_path,
            interactive=True
        )
        
        if not should_proceed:
            return False, "Aborted due to failed signature verification"
    
    # First check if this is a public key encrypted file
    encryption_method = detect_encryption_method(file_path)
    
    # If using public key encryption, don't prompt for password
    if encryption_method == "public_key":
        console.print("[cyan]Using private key for decryption[/cyan]")
        password = ""  # Empty password is fine for public key decryption
    else:
        # Get password if not provided - allow empty passwords
        if password is None:  # Check if None, not if falsy
            password = get_password(allow_empty=True)
            if password is None:  # Only None means error, "" is valid
                return False, "Password confirmation failed"
    
    # Handle output path in interactive mode
    if interactive and output is None:
        specify_output = Confirm.ask("Specify a custom output path? [Enter=No]", default=False)
        if specify_output:
            output = get_file_path("Enter output path", for_saving=True, must_exist=False)
    
    # Show what we're about to do
    console.print(f"\n[bold]Decrypting:[/bold] {filename}")
    if output:
        console.print(f"[bold]Output:[/bold] {output}")
    else:
        console.print("[bold]Output:[/bold] Original filename will be restored")
    
    try:
        # Decrypt with progress
        execute_with_progress(
            crypto_func,
            (file_path, output, password),
            task_description="Decrypting...",
        )
        
        console.print("\n[bold green]✓ File decrypted successfully![bold green]")
        return True, None
            
    except Exception as e:
        console.print("\n[bold red]✗ Decryption failed![bold red]")
        console.print(f"[red]Error: {str(e)}[red]")
        return False, str(e)

def detect_encryption_method(file_path: str) -> str:
    """
    Detect the encryption method used on a file
    
    Args:
        file_path: Path to the encrypted file
        
    Returns:
        String indicating the encryption method: "password", "public_key", or "unknown"
    """
    try:
        with open(file_path, 'rb') as f:
            # Read metadata length
            metadata_length_bytes = f.read(4)
            if len(metadata_length_bytes) != 4:
                return "unknown"
                
            metadata_length = int.from_bytes(metadata_length_bytes, 'big')
            if metadata_length <= 0 or metadata_length > 10000:
                return "unknown"
                
            # Try to parse the metadata
            metadata_bytes = f.read(metadata_length)
            metadata = json.loads(metadata_bytes.decode('utf-8'))
            
            # Check encryption method
            return metadata.get("encryption_method", "password")
    except Exception:
        return "unknown"

def handle_directory_encryption(
    crypto_func: Callable, 
    dir_path: str, 
    password: Optional[str] = None,
    interactive: bool = False
) -> Tuple[bool, Optional[str]]:
    """
    Handle directory encryption with consistent behavior across CLI and interactive modes
    
    Args:
        crypto_func: Directory encryption function to call
        dir_path: Path to the directory to encrypt
        password: Optional password (will prompt if None)
        interactive: Whether this is in interactive mode
        
    Returns:
        Tuple of (success, error_message)
    """
    # Get directory name for display
    dir_name = os.path.basename(dir_path)
    
    # Ask for encryption method
    use_public_key = False
    if interactive:
        console.print("\n[blue]Choose encryption method:[/blue]")
        console.print("1. Password (symmetric encryption)")
        console.print("2. Public key (encrypt for someone else)")
        choice = Prompt.ask("Select option", choices=["1", "2"], default="1")
        use_public_key = choice == "2"
    
    # Handle public key encryption
    trusted_key = None
    if use_public_key:
        # Get key manager
        key_manager = KeyManager()
        trusted_keys = key_manager.get_trusted_keys()
        
        if not trusted_keys:
            console.print("\n[bold yellow]No trusted public keys found![bold yellow]")
            console.print("[yellow]You need to import a public key first.[/yellow]")
            
            if interactive and Confirm.ask("Would you like to import a public key now?", default=True):
                # Show instructions for importing a key
                console.print("\n[blue]To import a public key:[/blue]")
                console.print("1. Go to Key Management menu")
                console.print("2. Select 'Import public key'")
                console.print("3. Follow the prompts to import a key\n")
                
                if Confirm.ask("Continue with password encryption instead?", default=True):
                    # Fall back to password encryption
                    use_public_key = False
                else:
                    return False, "No trusted keys available"
            else:
                return False, "No trusted keys available"
                
        # Show available trusted keys
        if use_public_key:  # Only proceed if we still want to use public key
            console.print("\n[blue]Available trusted keys:[/blue]")
            keys_list = []
            for idx, (alias, info) in enumerate(trusted_keys.items(), 1):
                fingerprint = info.get("fingerprint", "unknown")
                console.print(f"{idx}. {alias} ({fingerprint})")
                keys_list.append((alias, info))
            
            # Select key
            key_idx = int(Prompt.ask(
                "Select key number", 
                choices=[str(i) for i in range(1, len(keys_list) + 1)],
                default="1"
            ))
            
            alias, trusted_key = keys_list[key_idx - 1]
            console.print(f"[blue]Using key:[/blue] {alias}")
    else:
        # Get password if not provided - allow empty passwords
        if password is None:  # Check if None, not if falsy
            password = get_password(confirm=True, allow_empty=True)
            if password is None:  # Only None means error, "" is valid
                return False, "Password confirmation failed"
    
    # Output file path - use .sfc extension instead of .bin for consistency
    output_file = os.path.join(os.path.dirname(dir_path), f"{dir_name}_encrypted.sfc")
    console.print(f"\n[bold]Encrypting directory:[/bold] {dir_name}")
    console.print(f"[bold]Output:[/bold] {output_file}")
    console.print(f"[bold]Method:[/bold] {'Public key' if use_public_key else 'Password'}")
    
    try:
        # Call crypto function with the right parameters
        if use_public_key:
            # Pass None for password, trusted_key for recipient
            crypto_func(dir_path, None, trusted_key)
        else:
            # Fix: Always pass password explicitly to avoid None being passed
            crypto_func(dir_path, password=password)
        
        console.print("\n[bold green]✓ Directory encrypted successfully![bold green]")
        console.print(f"[green]Encrypted file saved to: {output_file}[green]")
        return True, None
        
    except Exception as e:
        console.print("\n[bold red]✗ Directory encryption failed![bold red]")
        console.print(f"[red]Error: {str(e)}[red]")
        return False, str(e)

def get_unique_directory_path(base_path: str) -> str:
    """
    Get a unique directory path by appending a number if it already exists
    
    Args:
        base_path: The base directory path
        
    Returns:
        A unique directory path that doesn't exist yet
    """
    if not os.path.exists(base_path):
        return base_path
        
    # Extract the parent and base name
    base_dir = os.path.dirname(base_path)
    base_name = os.path.basename(base_path)
    
    # Remove any existing numbered suffix pattern like "_1", "_2", etc.
    suffix_pattern = re.compile(r'_\d+$')
    clean_base_name = base_name
    if suffix_pattern.search(base_name):
        clean_base_name = suffix_pattern.sub('', base_name)
    
    # Add numbers to the ROOT directory name until we find an available path
    counter = 1
    while True:
        new_name = f"{clean_base_name}_{counter}"
        new_path = os.path.join(base_dir, new_name)
        if not os.path.exists(new_path):
            return new_path
        counter += 1

def handle_directory_decryption(
    crypto_func: Callable, 
    file_path: str, 
    password: Optional[str] = None,
    interactive: bool = False
) -> Tuple[bool, Optional[str]]:
    """
    Handle directory decryption with consistent behavior across CLI and interactive modes
    
    Args:
        crypto_func: Directory decryption function to call
        file_path: Path to the encrypted directory file
        password: Optional password (will prompt if None)
        interactive: Whether this is in interactive mode
        
    Returns:
        Tuple of (success, error_message)
    """
    # Check for signature and verify if exists
    if interactive:
        should_proceed = check_and_verify_signature_before_decryption(
            crypto_func.__self__,  # The SecureFileCrypto object
            file_path,
            interactive=True
        )
        
        if not should_proceed:
            return False, "Aborted due to failed signature verification"
    
    # First read the file metadata to determine encryption method
    encryption_method = detect_encryption_method(file_path)
    
    # Skip password prompt for public key encryption
    if encryption_method == "public_key":
        console.print("[cyan]Using private key for decryption[/cyan]")
        password = ""  # Empty password is fine for public key decryption
    elif encryption_method == "password" and password is None:
        if interactive:
            password = get_password(allow_empty=True)
        else:
            raise ValueError("Password required for password-based encryption")
    
    # Rest of the existing decryption logic...
    filename = os.path.basename(file_path)
    console.print(f"\n[bold]Decrypting archive:[/bold] {filename}")
    
    # Show encryption method
    console.print(f"[blue]Encryption method:[/blue] {encryption_method.title()}")
    if encryption_method == "public_key":
        console.print("[cyan]Using private key for decryption[/cyan]")

    # Verify this is actually an encrypted directory archive
    if not is_encrypted_directory_archive(file_path):
        if interactive and Confirm.ask(
            "This doesn't appear to be an encrypted directory archive. Try to decrypt as a regular file instead?",
            default=True
        ):
            # Use file decryption instead
            return handle_file_decryption(
                crypto_func.__self__.decrypt_file,  # Get the decrypt_file method from same object
                file_path,
                password,
                None,
                interactive
            )
        else:
            return False, "Not a valid encrypted directory archive"
    
    # Get filename for display
    filename = os.path.basename(file_path)
    
    # Get password if not provided - allow empty passwords
    if password is None:  # Check if None, not if falsy
        password = get_password(allow_empty=True)
    
    # Show what we're about to do
    console.print(f"\n[bold]Decrypting archive:[/bold] {filename}")
    
    # Get output directory name
    base_name = os.path.basename(file_path)
    parent_dir = os.path.dirname(file_path)
    
    # Extract the original directory name with improved logic
    original_name = None
    
    # Try to extract original name from filename patterns
    patterns = [
        (r'_encrypted\.sfc$', ''),  # Remove _encrypted.sfc
        (r'_encrypted\.bin$', ''),  # Remove _encrypted.bin
        (r'\.sfc$', ''),            # Remove .sfc extension
        (r'\.bin$', '')             # Remove .bin extension
    ]
    
    for pattern, replacement in patterns:
        if re.search(pattern, base_name, re.IGNORECASE):
            original_name = re.sub(pattern, replacement, base_name, flags=re.IGNORECASE)
            break
    
    # If no pattern matched, use fallback
    if original_name is None:
        # Default fallback with generic name
        original_name = f"{os.path.splitext(base_name)[0]}_extracted"
    
    # Allow custom output directory in interactive mode
    if interactive:
        use_default_output = Confirm.ask(
            f"Extract to '{original_name}' in the same folder? [Enter=Yes]", 
            default=True
        )
        
        if not use_default_output:
            custom_dir = get_directory_path(
                "Enter output directory path (or -e for explorer)", 
                must_exist=False
            )
            if custom_dir:
                output_dir = custom_dir
                suggested_path = output_dir
            else:
                # User canceled, use default
                suggested_path = os.path.join(parent_dir, original_name)
        else:
            suggested_path = os.path.join(parent_dir, original_name)
    else:
        suggested_path = os.path.join(parent_dir, original_name)
    
    # Ensure we have a unique directory path
    output_dir = get_unique_directory_path(suggested_path)
    
    # If the path was modified, inform the user with improved messaging
    if output_dir != suggested_path:
        renamed_dir = os.path.basename(output_dir)
        console.print(f"[yellow]Note: A directory named '{original_name}' already exists.[/yellow]")
        console.print(f"[yellow]Contents will be extracted to '{renamed_dir}' instead.[/yellow]")
    
    console.print(f"[bold]Output directory:[/bold] {output_dir}")
    
    try:
        # Call directly without progress wrapper - the function has its own progress reporting
        crypto_func(file_path, password, output_dir)
        
        # Verify extraction succeeded by checking if directory has content
        if os.path.exists(output_dir) and os.listdir(output_dir):
            console.print("\n[bold green]✓ Directory decrypted successfully![bold green]")
            console.print(f"[green]Files extracted to: {output_dir}[green]")
            
            # Show file count
            file_count = sum(len(files) for _, _, files in os.walk(output_dir))
            dir_count = sum(len(dirs) for _, dirs, _ in os.walk(output_dir))
            console.print(f"[green]Extracted {file_count} files in {dir_count} directories[green]")
            
            return True, None
        else:
            console.print("\n[bold yellow]⚠ Directory was decrypted but appears to be empty![bold yellow]")
            return True, "Extracted directory is empty"
        
    except Exception as e:
        error_message = str(e)
        console.print("\n[bold red]✗ Directory decryption failed![bold red]")
        
        # Clean up empty output directory if it was created
        if os.path.exists(output_dir) and not os.listdir(output_dir):
            try:
                os.rmdir(output_dir)
                console.print("[dim]Removed empty output directory[dim]")
            except Exception:
                pass
        
        # Provide more detailed error information for common errors
        if "not a valid ZIP file" in error_message or "invalid ZIP file" in error_message:
            console.print("[red]The file couldn't be extracted as a ZIP archive.[/red]")
            console.print("[yellow]Possible reasons:[/yellow]")
            console.print("  • Incorrect password")
            console.print("  • The file is not an encrypted directory")
            console.print("  • The encrypted file is corrupted")
            
            # Offer to try file decryption instead
            if interactive and Confirm.ask("Try to decrypt as a regular file instead?", default=True):
                return handle_file_decryption(
                    crypto_func.__self__.decrypt_file,  # Get the decrypt_file method from same object
                    file_path,
                    password,
                    None,
                    interactive
                )
        else:
            console.print(f"[red]Error: {error_message}[red]")
            
        return False, str(e)

def handle_key_generation(
    key_manager,
    output_dir: Optional[str] = None,
    force: bool = False,
    interactive: bool = False
) -> Tuple[bool, Optional[str], Optional[bytes], Optional[bytes]]:
    """
    Handle key generation with consistent behavior across CLI and interactive modes
    
    Args:
        key_manager: The KeyManager object
        output_dir: Optional directory for key output
        force: Whether to force overwrite existing keys
        interactive: Whether this is in interactive mode
        
    Returns:
        Tuple of (success, error_message, private_key_pem, public_key_pem)
    """
    # Handle output directory selection
    if not output_dir:
        output_dir = key_manager.keys_dir
    
    # Check for existing keys
    keys_exist = (os.path.exists(key_manager.private_key_path) or 
                  os.path.exists(key_manager.public_key_path))
    
    # In interactive mode or when keys exist and force is False, confirm overwrite
    if keys_exist and (interactive or not force):
        if not Confirm.ask("Keys already exist! Overwrite? [Enter=Yes]", default=True):
            console.print("[yellow]Key generation canceled.[/yellow]")
            return False, "Key generation canceled", None, None 
    
    # In interactive mode with custom directory
    if interactive and output_dir == key_manager.keys_dir:
        use_default = Confirm.ask("Save new keys to default location? [Enter=Yes]", default=True)
        if not use_default:
            directory = get_directory_path("Enter directory path", must_exist=True)
            if directory is None:
                return False, "Directory selection canceled", None, None
            output_dir = directory
    
    try:
        # Generate keys with progress
        private_key_pem, public_key_pem = execute_with_progress(
            key_manager.generate_keypair,
            (output_dir,),
            task_description="Generating new RSA-3072 keypair...",
        )
        
        console.print("\n[bold green]✓ Key pair generated successfully![bold green]")
        console.print(f"[green]Keys saved to: {output_dir}[green]")
        
        # Show key info
        from rich.table import Table
        table = Table(title="Key Information")
        table.add_column("File", style="cyan")
        table.add_column("Type", style="green")
        table.add_column("Usage", style="yellow")
        
        table.add_row(
            "private_key.pem", 
            "RSA-3072 Private Key",
            "For future security features"
        )
        table.add_row(
            "public_key.pem",
            "RSA-3072 Public Key",
            "For future security features"
        )
        
        console.print(table)
        return True, None, private_key_pem, public_key_pem
            
    except Exception as e:
        console.print("\n[bold red]✗ Key generation failed![bold red]")
        console.print(f"[red]Error: {str(e)}[red]")
        return False, str(e), None, None

def run_interactive_operation(
    get_path_func: Callable,
    operation_handler: Callable,
    path_prompt: str,   
    operation_args: tuple = (),
    must_exist: bool = True,
    retry_on_password_error: bool = False
):
    """
    Run an interactive operation with uniform path handling
    
    Args:
        get_path_func: Function to get the path (get_file_path or get_directory_path)
        operation_handler: Handler function to execute with the path
        path_prompt: Prompt to show when getting the path
        operation_args: Additional args for the operation handler
        must_exist: Whether the path must exist
        retry_on_password_error: Whether to retry on password error
    """
    # Get the path using the provided function
    path = get_path_func(path_prompt, must_exist=must_exist)
    if path is None:
        return
    
    # Call the operation handler with the path and any additional args
    # The first arg in operation_args should be the crypto_func
    crypto_func = operation_args[0]
    success, error = operation_handler(crypto_func, path, interactive=True)
    
    # Handle password retry for decryption operations
    if not success and retry_on_password_error:
        if "password" in str(error).lower() or "invalid" in str(error).lower():
            from rich.prompt import Confirm
            if Confirm.ask("Try again with a different password?", default=True):
                # Recursive call to try again - use the same path
                run_interactive_operation(
                    lambda *args, **kwargs: path,  # Return the same path
                    operation_handler,
                    path_prompt,
                    operation_args,
                    must_exist,
                    retry_on_password_error
                )

def handle_file_signature(
    sign_func: Callable,
    file_path: str,
    output_path: Optional[str] = None,
    interactive: bool = False
) -> Tuple[bool, Optional[str]]:
    """
    Handle file signature creation with consistent behavior
    
    Args:
        sign_func: Signature function to call
        file_path: Path to file to sign
        output_path: Optional path for signature file
        interactive: Whether this is in interactive mode
        
    Returns:
        Tuple of (success, error_message)
    """
    # Get filename for display
    filename = os.path.basename(file_path)
    
    # Determine signature path
    if not output_path:
        if interactive:
            use_default = Confirm.ask(f"Save signature as '{filename}.sig'? [Enter=Yes]", default=True)
            if not use_default:
                output_path = get_output_path(file_path, default_ext=".sig")
                if not output_path:
                    return False, "Signature path selection canceled"
            else:
                output_path = f"{file_path}.sig"
        else:
            output_path = f"{file_path}.sig"
    
    # Check for private key
    key_manager = KeyManager()
    private_key_path = key_manager.private_key_path
    
    if not os.path.exists(private_key_path):
        console.print("[bold yellow]No private key found![/bold yellow]")
        
        if interactive and Confirm.ask("Generate a new keypair now?", default=True):
            # Generate keypair
            from utils.operation_manager import handle_key_generation
            success, error, _, _ = handle_key_generation(key_manager, interactive=True)
            if not success:
                return False, error or "Failed to generate keys"
        else:
            return False, "No private key available"
    
    # Show what we're about to do
    console.print(f"\n[bold]Signing:[/bold] {filename}")
    console.print(f"[bold]Signature file:[/bold] {output_path}")
    
    try:
        # Sign with progress
        execute_with_progress(
            sign_func,
            (file_path, output_path),
            task_description="Signing file...",
        )
        
        console.print("\n[bold green]✓ File signed successfully![bold green]")
        console.print(f"[green]Signature saved to: {output_path}[/green]")
        return True, None
            
    except Exception as e:
        console.print("\n[bold red]✗ Signature creation failed![bold red]")
        console.print(f"[red]Error: {str(e)}[/red]")
        return False, str(e)

def handle_signature_verification(
    verify_func: Callable,
    file_path: str,
    signature_path: Optional[str] = None,
    public_key_path: Optional[str] = None,
    interactive: bool = False
) -> Tuple[bool, Optional[str], bool]:
    """
    Handle signature verification with consistent behavior
    
    Args:
        verify_func: Verification function to call
        file_path: Path to file to verify
        signature_path: Path to signature file (will try {file_path}.sig if None)
        public_key_path: Path to public key file (None for default)
        interactive: Whether this is in interactive mode
        
    Returns:
        Tuple of (success, error_message, verification_result)
    """
    # Get filename for display
    filename = os.path.basename(file_path)
    
    # Determine signature path
    if not signature_path:
        default_sig_path = f"{file_path}.sig"
        
        if os.path.exists(default_sig_path):
            signature_path = default_sig_path
            console.print(f"[blue]Found signature file:[/blue] {os.path.basename(default_sig_path)}")
        elif interactive:
            console.print("[yellow]No signature file specified and no default found.[/yellow]")
            signature_path = get_file_path("Enter signature file path", must_exist=True)
            if not signature_path:
                return False, "Signature file selection canceled", False
        else:
            return False, f"Signature file not found: {default_sig_path}", False
    
    # Determine which public key to use
    if public_key_path is None:
        key_manager = KeyManager()
        default_key_path = key_manager.public_key_path
        
        if os.path.exists(default_key_path):
            public_key_path = default_key_path
        elif interactive:
            console.print("[yellow]No public key found for verification.[/yellow]")
            
            # Ask whether to use a trusted key
            use_trusted = Confirm.ask("Use a trusted key for verification? [Enter=Yes]", default=True)
            if use_trusted:
                # Show available trusted keys
                trusted_keys = key_manager.get_trusted_keys()
                if not trusted_keys:
                    console.print("[yellow]No trusted keys available.[/yellow]")
                    return False, "No public key available for verification", False
                
                console.print("\n[blue]Available trusted keys:[/blue]")
                keys_list = []
                for idx, (alias, info) in enumerate(trusted_keys.items(), 1):
                    fingerprint = info.get("fingerprint", "unknown")
                    console.print(f"{idx}. {alias} ({fingerprint})")
                    keys_list.append((alias, info))
                
                # Select key
                key_idx = int(Prompt.ask(
                    "Select key number", 
                    choices=[str(i) for i in range(1, len(keys_list) + 1)],
                    default="1"
                ))
                
                alias, key_info = keys_list[key_idx - 1]
                public_key_path = key_info.get("path")
                console.print(f"[blue]Using key:[/blue] {alias}")
            else:
                # Let user select a key file
                public_key_path = get_file_path("Select public key file", must_exist=True)
                if not public_key_path:
                    return False, "Public key selection canceled", False
        else:
            return False, "No public key available for verification", False
    
    # Show what we're about to do
    console.print(f"\n[bold]Verifying:[/bold] {filename}")
    console.print(f"[bold]Signature:[/bold] {signature_path}")
    console.print(f"[bold]Public key:[/bold] {public_key_path}")
    
    try:
        # Verify with progress
        is_valid, signature_info = execute_with_progress(
            verify_func,
            (file_path, signature_path, public_key_path),
            task_description="Verifying signature...",
        )
        
        if is_valid:
            console.print("\n[bold green]✓ Signature is valid![bold green]")
            
            # Show signature info
            if signature_info:
                console.print("[blue]Signature information:[/blue]")
                if "file_name" in signature_info:
                    console.print(f"  Original filename: {signature_info['file_name']}")
                if "created_at" in signature_info:
                    import datetime
                    created_time = datetime.datetime.fromtimestamp(signature_info['created_at'])
                    console.print(f"  Created: {created_time.strftime('%Y-%m-%d %H:%M:%S')}")
                if "algorithm" in signature_info:
                    console.print(f"  Algorithm: {signature_info['algorithm']}")
            
            return True, None, True
        else:
            console.print("\n[bold red]✗ Signature is invalid![/bold red]")
            console.print("[red]The file may have been tampered with or the wrong public key was used.[/red]")
            return True, None, False
            
    except Exception as e:
        console.print("\n[bold red]✗ Verification failed![bold red]")
        console.print(f"[red]Error: {str(e)}[red]")
        return False, str(e), False

def check_and_verify_signature_before_decryption(
    crypto_obj: object,
    file_path: str,
    interactive: bool = False
) -> bool:
    """
    Check if a signature exists for a file that's being decrypted and verify it
    
    Args:
        crypto_obj: The crypto object with verify_signature method
        file_path: Path to the encrypted file
        interactive: Whether in interactive mode
        
    Returns:
        True if should proceed with decryption, False if should abort
    """
    if not interactive:
        return True
    
    # Check for signature file
    signature_path = f"{file_path}.sig"
    if not os.path.exists(signature_path):
        return True  # No signature, proceed with decryption
    
    # Signature exists, ask if user wants to verify
    console.print(f"[yellow]Signature file found for the encrypted file:[/yellow] {os.path.basename(signature_path)}")
    verify_signature = Confirm.ask("Verify file signature before decryption?", default=True)
    
    if not verify_signature:
        return True  # User chose not to verify, proceed with decryption
    
    # Determine which public key to use
    key_manager = KeyManager()
    public_key_path = None
    
    if os.path.exists(key_manager.public_key_path):
        public_key_path = key_manager.public_key_path
        console.print("[blue]Using your public key for verification...[/blue]")
    else:
        # Ask whether to use a trusted key
        trusted_keys = key_manager.get_trusted_keys()
        if trusted_keys:
            use_trusted = Confirm.ask("No public key found. Use a trusted key? [Enter=Yes]", default=True)
            if use_trusted:
                console.print("\n[blue]Available trusted keys:[/blue]")
                keys_list = []
                for idx, (alias, info) in enumerate(trusted_keys.items(), 1):
                    fingerprint = info.get("fingerprint", "unknown")
                    console.print(f"{idx}. {alias} ({fingerprint})")
                    keys_list.append((alias, info))
                
                # Select key
                key_idx = int(Prompt.ask(
                    "Select key number", 
                    choices=[str(i) for i in range(1, len(keys_list) + 1)],
                    default="1"
                ))
                
                alias, key_info = keys_list[key_idx - 1]
                public_key_path = key_info.get("path")
        
    if not public_key_path:
        console.print("[yellow]No public key available for verification.[/yellow]")
        return Confirm.ask("Continue with decryption without verification?", default=False)
    
    # Verify the signature
    try:
        console.print("[blue]Verifying signature before decryption...[/blue]")
        is_valid, signature_info = crypto_obj.verify_signature(file_path, signature_path, public_key_path)
        
        if is_valid:
            console.print("[bold green]✓ Signature is valid! Proceeding with decryption.[/bold green]")
            return True
        else:
            console.print("[bold red]✗ Signature is INVALID![/bold red]")
            console.print("[bold red]WARNING: This file may have been tampered with![/bold red]")
            console.print("[bold yellow]Decryption of a tampered file could be dangerous.[/bold yellow]")
            
            # Ask if user wants to continue anyway
            proceed = Confirm.ask("Do you want to proceed with decryption anyway?", default=False)
            if not proceed:
                console.print("[yellow]Decryption cancelled for security reasons.[/yellow]")
                
            return proceed
            
    except Exception as e:
        console.print(f"[red]Error verifying signature: {str(e)}[/red]")
        
        # Ask if user wants to continue despite verification error
        proceed = Confirm.ask("Unable to verify. Do you want to proceed anyway?", default=False)
        if not proceed:
            console.print("[yellow]Decryption cancelled for security reasons.[/yellow]")
            
        return proceed

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
        
    output_path_input = typer.prompt("Enter output path (or -e/-ef for file explorer)")
    
    # Check if user wants to use file explorer for output path
    if output_path_input.lower() in ['-e', '-ef', '--explorer']:
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
