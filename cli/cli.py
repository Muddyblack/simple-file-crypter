import os
import sys
from pathlib import Path

import typer
from click.exceptions import Abort
from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.traceback import install

from core.crypto import SecureFileCrypto
from core.keys import KeyManager
from ui.banner import print_banner
from ui.icons import get_operation_status_icon
from ui.keys_display import display_keys_as_panels
from ui.menu import display_menu, display_menu_header
from ui.progress import show_processing_animation
from utils.input_handlers import get_directory_path, get_file_path
from utils.key_loader import load_default_keys
from utils.keyboard_interrupt import handle_keyboard_interrupt
from utils.operation_manager import (
    handle_directory_decryption,
    handle_directory_encryption,
    handle_file_decryption,
    handle_file_encryption,
    handle_file_signature,
    handle_key_generation,
    handle_signature_verification,
    run_interactive_operation,
)
from utils.path_detector import get_smart_path, is_encrypted_directory_archive, is_encrypted_file

# Module-level argument/option definitions
FILE_ARGUMENT = typer.Argument(None, help="File to encrypt", exists=True)
FILE_OUTPUT_OPTION = typer.Option(None, "--output", "-o", help="Output filename")
PASSWORD_OPTION = typer.Option(None, "--password", "-p", help="Encryption password")
DIRECTORY_ARGUMENT = typer.Argument(None, help="Directory to encrypt", exists=True)
FORCE_OPTION = typer.Option(False, "--force", "-f", help="Force overwrite existing keys")

# Install rich traceback handler for beautiful error messages
install(show_locals=False)

# Initialize Typer app
app = typer.Typer(help="Secure File Crypter - Encrypt and decrypt files with strong security")
console = Console()

# Global state
crypto = SecureFileCrypto()
key_manager = KeyManager()
private_key_pem = None
public_key_pem = None

@app.command("interactive")
@handle_keyboard_interrupt
def start_interactive_mode():
    """Start interactive menu mode"""
    global private_key_pem, public_key_pem
    
    print_banner()
    
    # Load default keys
    private_key_pem, public_key_pem = load_default_keys(crypto)
    
    # Define menu options - simplified with smart operations
    menu_options = [
        ("1", "Encrypt/Decrypt file or directory", smart_crypto_operation),
        ("2", "Sign/Verify files", signature_menu),
        ("3", "Generate new keypair", operation_generate_keys),
        ("4", "Key management", operation_key_management),
        ("5", "Exit", None)
    ]
    
    while True:
        console.print()
        
        # Use the new menu display helper
        table = display_menu(menu_options, "Main Menu")
        console.print(table)
        
        try:
            choices = [option[0] for option in menu_options]
            choice = Prompt.ask("\nEnter your choice [Enter=Exit]", choices=choices, default="5")
        except (KeyboardInterrupt, Abort):
            # Handle Ctrl+C at menu level - exit program
            console.print("\n[bold blue]Goodbye![/bold blue]")
            break
        
        if choice == "5":
            console.print("[bold blue]Goodbye![/bold blue]")
            break
            
        # Find and execute the selected operation
        for option, _, operation_func in menu_options:
            if choice == option and operation_func is not None:
                try:
                    operation_func()
                except (KeyboardInterrupt, Abort):
                    # Handle Ctrl+C during an operation - return to menu
                    console.print("\n[yellow]Operation cancelled. Returning to menu...[/yellow]")
                except Exception as e:
                    console.print("\n[bold red]An error occurred:[/bold red]")
                    console.print(f"[red]Error: {str(e)}[/red]")
                break

@handle_keyboard_interrupt
def smart_crypto_operation():
    """Smart operation that automatically detects file/directory and encrypt/decrypt"""
    display_menu_header("Smart Crypto", "Main Menu")
    console.print("This will automatically detect if you want to encrypt or decrypt a file or directory")
    
    # Get path with smart detection
    path, path_type = get_smart_path("Enter path to process")
    
    # If path selection was cancelled
    if path is None or path_type is None:
        return
    
    # Determine if we're encrypting or decrypting based on the file type
    is_encrypted = False
    is_dir_archive = False
    
    if path_type == "file" and os.path.exists(path):
        is_encrypted = is_encrypted_file(path)
        is_dir_archive = is_encrypted_directory_archive(path)
    
    # Handle different scenarios
    if path_type == "file":
        if is_dir_archive:
            # Handle encrypted directory archive
            console.print("[blue]Detected:[/blue] This appears to be an [bold]encrypted directory archive[/bold]")
            run_interactive_operation(
                lambda *args, **kwargs: path,  # Lambda to return the path we already have
                handle_directory_decryption,
                "Encrypted directory archive",
                (crypto.decrypt_directory,),
                must_exist=True,
                retry_on_password_error=True
            )
        
        elif is_encrypted:
            # Handle encrypted regular file
            console.print("[blue]Detected:[/blue] This appears to be an [bold]encrypted file[/bold]")
            run_interactive_operation(
                lambda *args, **kwargs: path,  # Lambda to return the path we already have
                handle_file_decryption,
                "File to decrypt",
                (crypto.decrypt_file,),
                must_exist=True,
                retry_on_password_error=True
            )
        
        else:
            # Handle unencrypted file (encrypt)
            console.print("[blue]Detected:[/blue] This appears to be an [bold]unencrypted file[/bold]")
            run_interactive_operation(
                lambda *args, **kwargs: path,  # Lambda to return the path we already have
                handle_file_encryption,
                "File to encrypt",
                (crypto.encrypt_file,),
                must_exist=True
            )
    
    elif path_type == "directory":
        # Directories are always encrypted, not decrypted directly
        console.print("[blue]Detected:[/blue] This is a [bold]directory[/bold]")
        run_interactive_operation(
            lambda *args, **kwargs: path,  # Lambda to return the path we already have
            handle_directory_encryption,
            "Directory to encrypt",
            (crypto.encrypt_directory,),
            must_exist=True
        )
    else:
        console.print("[red]Error: Unknown path type.[/red]")

@handle_keyboard_interrupt
def operation_encrypt_file():
    """Interactive file encryption operation"""
    run_interactive_operation(
        get_file_path,
        handle_file_encryption,
        "Enter file path",
        (crypto.encrypt_file,),  # Pass as a tuple with the crypto function first
        must_exist=True
    )

@handle_keyboard_interrupt
def operation_decrypt_file():
    """Interactive file decryption operation"""
    run_interactive_operation(
        get_file_path,
        handle_file_decryption,
        "Enter encrypted file path",
        (crypto.decrypt_file,),  # Pass as a tuple with the crypto function first
        must_exist=True,
        retry_on_password_error=True
    )

@handle_keyboard_interrupt
def operation_encrypt_dir():
    """Interactive directory encryption operation"""
    run_interactive_operation(
        get_directory_path,
        handle_directory_encryption,
        "Enter directory path",
        (crypto.encrypt_directory,),  # Pass as a tuple with the crypto function first
        must_exist=True
    )

@handle_keyboard_interrupt
def operation_decrypt_dir():
    """Interactive directory decryption operation"""
    run_interactive_operation(
        get_file_path,
        handle_directory_decryption,
        "Enter encrypted archive path",
        (crypto.decrypt_directory,),  # Pass as a tuple with the crypto function first
        must_exist=True,
        retry_on_password_error=True
    )

@handle_keyboard_interrupt
def operation_generate_keys():
    """Interactive key generation operation"""
    display_menu_header("Generate New Keypair", "Main Menu")
    global private_key_pem, public_key_pem
    key_manager = KeyManager()
    
    # Use the unified handler with interactive flag
    success, error, priv_key, pub_key = handle_key_generation(
        key_manager, 
        interactive=True
    )
    
    if success:
        private_key_pem = priv_key
        public_key_pem = pub_key


# ===== Key management interactive functions =====

@handle_keyboard_interrupt
def operation_key_management():
    """Interactive key management submenu"""
    # Define submenu options
    submenu_options = [
        ("1", "List all keys", operation_list_keys),
        ("2", "Import public key", operation_import_key),
        ("3", "Export public key", operation_export_key),
        ("4", "Delete trusted key", operation_delete_key),
        ("5", "Revoke trusted key", operation_revoke_key),
        ("6", "Back to main menu", None)
    ]
    
    while True:
        console.print()
        
        # Pass empty or None for parent to avoid duplication
        table = display_menu(submenu_options, "Key Management", parent=None)
        console.print(table)
        
        try:
            choices = [option[0] for option in submenu_options]
            choice = Prompt.ask("\nEnter your choice [Enter=Back]", choices=choices, default="6")
        except (KeyboardInterrupt, Abort):
            # Handle Ctrl+C - return to main menu
            console.print("\n[yellow]Returning to main menu...[/yellow]")
            break
        
        if choice == "6":
            break
            
        # Find and execute the selected operation
        for option, _, operation_func in submenu_options:
            if choice == option and operation_func is not None:
                try:
                    operation_func()
                except (KeyboardInterrupt, Abort):
                    # Handle Ctrl+C during an operation - return to menu
                    console.print("\n[yellow]Operation cancelled.[/yellow]")
                except Exception as e:
                    console.print("\n[bold red]An error occurred:[/bold red]")
                    console.print(f"[red]Error: {str(e)}[/red]")
                break

@handle_keyboard_interrupt
def operation_list_keys():
    """Interactive list keys operation"""
    try:
        display_menu_header("Available Keys", "Key Management")
        
        # Get keys and display them using fancy panels instead of plain text
        keys = key_manager.get_available_keys()
        display_keys_as_panels(keys)
        
        # Pause for user to view the information
        Prompt.ask("\nPress Enter to continue")
        
    except Exception as e:
        icon = get_operation_status_icon("error")
        console.print(f"[bold red]{icon} Error listing keys:[/bold red] {str(e)}")

@handle_keyboard_interrupt
def operation_import_key():
    """Interactive import public key operation"""
    try:
        display_menu_header("Import Public Key", "Key Management", "Main Menu")
        
        key_path = get_file_path("Enter public key file path", must_exist=True)
        if not key_path:
            icon = get_operation_status_icon("warning")
            console.print(f"[yellow]{icon} Operation cancelled.[/yellow]")
            return
            
        # Verify it's actually a public key with animation
        show_processing_animation("Verifying key")
        valid, key_type = key_manager.verify_key(key_path)
        if not valid or key_type != 'public':
            icon = get_operation_status_icon("error")
            console.print(f"[bold red]{icon} Error:[/bold red] The provided file is not a valid public key.")
            return
            
        alias = Prompt.ask("Enter an alias for this key")
        
        # Import with animation
        show_processing_animation("Importing key")
        imported_path = key_manager.import_public_key(key_path, alias)
        fingerprint = key_manager.get_key_fingerprint(imported_path)
        
        icon = get_operation_status_icon("success")
        console.print(f"[green]{icon} Public key imported successfully![/green]")
        console.print(f"[blue]Alias:[/blue] {alias}")
        console.print(f"[blue]Fingerprint:[/blue] {fingerprint}")
        console.print(f"[blue]Saved to:[/blue] {imported_path}")
        
        # Pause for user to view the information
        Prompt.ask("\nPress Enter to continue")
        
    except Exception as e:
        icon = get_operation_status_icon("error")
        console.print(f"[bold red]{icon} Error importing key:[/bold red] {str(e)}")

@handle_keyboard_interrupt
def operation_export_key():
    """Interactive export public key operation"""
    try:
        # First check if we have a public key
        if not key_manager.public_key_path.exists():
            if Confirm.ask("No public key found. Generate a new keypair?", default=True):
                operation_generate_keys()
            else:
                console.print("[yellow]Operation cancelled.[/yellow]")
                return
                
        # Get export location
        output_path = Prompt.ask("Enter path to save the public key", default=str(Path.home() / "public_key.pem"))
        
        exported_path = key_manager.export_public_key(output_path)
        fingerprint = key_manager.get_key_fingerprint(exported_path)
        
        console.print("[green]Public key exported successfully![/green]")
        console.print(f"[blue]Fingerprint:[/blue] {fingerprint}")
        console.print(f"[blue]Saved to:[/blue] {exported_path}")
    except Exception as e:
        console.print(f"[bold red]Error exporting key:[/bold red] {str(e)}")

@handle_keyboard_interrupt
def operation_delete_key():
    """Interactive delete trusted key operation"""
    try:
        # Get list of trusted keys
        trusted_keys = key_manager.get_trusted_keys()
        
        if not trusted_keys:
            console.print("[yellow]No trusted keys found.[/yellow]")
            return
            
        console.print("[blue]Available trusted keys:[/blue]")
        for alias in trusted_keys:
            fingerprint = trusted_keys[alias].get("fingerprint", "unknown")
            console.print(f"  - {alias} ({fingerprint})")
            
        alias = Prompt.ask("Enter alias of key to delete")
        
        if alias not in trusted_keys:
            console.print(f"[yellow]Key not found:[/yellow] {alias}")
            return
            
        if Confirm.ask(f"Are you sure you want to delete the key '{alias}'?", default=False):
            success = key_manager.delete_trusted_key(alias)
            if success:
                console.print(f"[green]Successfully deleted trusted key:[/green] {alias}")
            else:
                console.print("[yellow]Failed to delete key.[/yellow]")
        else:
            console.print("[yellow]Operation cancelled.[/yellow]")
    except Exception as e:
        console.print(f"[bold red]Error deleting key:[/bold red] {str(e)}")

@handle_keyboard_interrupt
def operation_revoke_key():
    """Interactive revoke trusted key operation"""
    try:
        # Get list of trusted keys
        trusted_keys = key_manager.get_trusted_keys()
        
        if not trusted_keys:
            console.print("[yellow]No trusted keys found.[/yellow]")
            return
            
        console.print("[blue]Available trusted keys:[/blue]")
        for alias in trusted_keys:
            fingerprint = trusted_keys[alias].get("fingerprint", "unknown")
            console.print(f"  - {alias} ({fingerprint})")
            
        alias = Prompt.ask("Enter alias of key to revoke")
        
        if alias not in trusted_keys:
            console.print(f"[yellow]Key not found:[/yellow] {alias}")
            return
            
        if Confirm.ask(f"Are you sure you want to revoke the key '{alias}'?", default=False):
            success = key_manager.revoke_key(alias)
            if success:
                console.print(f"[green]Successfully revoked trusted key:[/green] {alias}")
            else:
                console.print("[yellow]Failed to revoke key.[/yellow]")
        else:
            console.print("[yellow]Operation cancelled.[/yellow]")
    except Exception as e:
        console.print(f"[bold red]Error revoking key:[/bold red] {str(e)}")

@handle_keyboard_interrupt
def signature_menu():
    """Interactive signature submenu"""
    # Define submenu options
    submenu_options = [
        ("1", "Sign a file", operation_sign_file),
        ("2", "Verify file signature", operation_verify_signature),
        ("3", "Back to main menu", None)
    ]
    
    while True:
        console.print()
        
        # Pass empty or None for parent to avoid duplication
        table = display_menu(submenu_options, "File Signatures", parent="Main Menu")
        console.print(table)
        
        try:
            choices = [option[0] for option in submenu_options]
            choice = Prompt.ask("\nEnter your choice [Enter=Back]", choices=choices, default="3")
        except (KeyboardInterrupt, Abort):
            # Handle Ctrl+C - return to main menu
            console.print("\n[yellow]Returning to main menu...[/yellow]")
            break
        
        if choice == "3":
            break
            
        # Find and execute the selected operation
        for option, _, operation_func in submenu_options:
            if choice == option and operation_func is not None:
                try:
                    operation_func()
                except (KeyboardInterrupt, Abort):
                    # Handle Ctrl+C during an operation - return to menu
                    console.print("\n[yellow]Operation cancelled.[/yellow]")
                except Exception as e:
                    console.print("\n[bold red]An error occurred:[/bold red]")
                    console.print(f"[red]Error: {str(e)}[/red]")
                break

@handle_keyboard_interrupt
def operation_sign_file():
    """Interactive file signing operation"""
    display_menu_header("Sign a File", "File Signatures", "Main Menu")
    console.print("This operation creates a digital signature for a file using your private key.")
    console.print("The signature can be used to verify the file hasn't been tampered with.")
    
    # Get file path
    file_path = get_file_path("Select file to sign", must_exist=True)
    if not file_path:
        return
    
    # Handle signing
    handle_file_signature(crypto.sign_file, file_path, interactive=True)

@handle_keyboard_interrupt
def operation_verify_signature():
    """Interactive signature verification operation"""
    display_menu_header("Verify File Signature", "File Signatures", "Main Menu")
    console.print("This operation verifies that a file matches its digital signature.")
    
    # Get file path
    file_path = get_file_path("Select file to verify", must_exist=True)
    if not file_path:
        return
    
    # Look for default signature file
    default_sig = f"{file_path}.sig"
    sig_path = None
    
    if os.path.exists(default_sig):
        if Confirm.ask(f"Use signature file '{os.path.basename(default_sig)}'? [Enter=Yes]", default=True):
            sig_path = default_sig
    
    if not sig_path:
        sig_path = get_file_path("Select signature file", must_exist=True)
        if not sig_path:
            return
    
    # Handle verification
    success, _, is_valid = handle_signature_verification(crypto.verify_signature, file_path, sig_path, interactive=True)
    
    # Inform the user of the result
    if success and is_valid:
        if Confirm.ask("\nPress Enter to continue", default=True):
            return

if __name__ == "__main__":
    # If no arguments, start interactive mode
    if len(sys.argv) == 1:
        try:
            start_interactive_mode()
        except KeyboardInterrupt:
            console.print("\n[bold blue]Goodbye![bold blue]")
            sys.exit(0)
    else:
        try:
            app()
        except KeyboardInterrupt:
            console.print("\n[yellow]Operation cancelled.[/yellow]")
            sys.exit(1)