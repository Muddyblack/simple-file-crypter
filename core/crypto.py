import base64
import json
import os
import re
import secrets
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

from core.keys import KeyManager
from utils.archiver import DirectoryArchiver
from utils.threading_utils import thread_pool


class SecureFileCrypto:
    """
    A secure file encryption system using modern cryptographic practices:
    - AES-256-GCM for authenticated encryption
    - Scrypt for key derivation
    - Secure random number generation
    - Authenticated metadata
    """
    
    def __init__(self):
        self.CHUNK_SIZE = 1024 * 1024  # 1MB chunks for memory efficiency
        self.keys_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "keys"))
        
        # Create keys directory if it doesn't exist
        os.makedirs(self.keys_dir, exist_ok=True)
        
        self.private_key_path = os.path.join(self.keys_dir, "private_key.pem")
        self.public_key_path = os.path.join(self.keys_dir, "public_key.pem")
        self.archiver = DirectoryArchiver()
        
    def _generate_salt(self) -> bytes:
        """Generate a cryptographically secure salt"""
        return secrets.token_bytes(32)
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive an encryption key from password using Scrypt
        Uses memory-hard parameters for enhanced security
        """
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**18,  # CPU/memory cost parameter
            r=8,      # Block size parameter
            p=1       # Parallelization parameter
        )
        return kdf.derive(password.encode())
    
    def _encrypt_chunk(self, key: bytes, chunk: bytes, nonce: bytes) -> bytes:
        """Encrypt a single chunk using AES-GCM"""
        aesgcm = AESGCM(key)
        return aesgcm.encrypt(nonce, chunk, None)
    
    def _decrypt_chunk(self, key: bytes, chunk: bytes, nonce: bytes) -> bytes:
        """Decrypt a single chunk using AES-GCM"""
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, chunk, None)
    
    def _hash_data(self, data: bytes) -> bytes:
        """Calculate SHA-256 hash of data"""
        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(data)
        return hasher.finalize()
    
    def _check_password_strength(self, password: str) -> bool:
        """
        Verify password meets minimum security requirements
        Returns True if password is strong enough
        """
        if len(password) < 8:
            return False
            
        # Check for complexity (at least 3 of 4 character types)
        checks = [
            re.search(r'[A-Z]', password) is not None,  # uppercase
            re.search(r'[a-z]', password) is not None,  # lowercase
            re.search(r'[0-9]', password) is not None,  # digits
            re.search(r'[^A-Za-z0-9]', password) is not None  # special chars
        ]
        return sum(checks) >= 3
    
    def _secure_delete_file(self, file_path: str) -> None:
        """Securely delete a file by overwriting with random data before deletion"""
        if not os.path.exists(file_path):
            return
            
        # Get file size
        file_size = os.path.getsize(file_path)
        
        # Overwrite with random data multiple times
        for _ in range(3):
            with open(file_path, 'wb') as f:
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())
                
        # Delete the file
        os.unlink(file_path)
    
    def encrypt_file(self, input_path: str, output_path: str, password=None, trusted_key=None) -> None:
        """
        Encrypt a file using authenticated encryption
        
        Args:
            input_path: Path to file to encrypt
            output_path: Path to save encrypted file
            password: Optional encryption password
            trusted_key: Optional trusted key info for public key encryption
        """
        # Validate that at least one encryption method is provided
        if password is None and trusted_key is None:
            raise ValueError("Either password or trusted key must be provided")
            
        # Add file integrity hash
        file_hash = self._calculate_file_hash(input_path)
        
        # Get original filename for restoration during decryption
        original_filename = os.path.basename(input_path)
        
        # Determine encryption method
        encryption_method = "password" if password else "public_key"
        
        if encryption_method == "password":
            # Password-based encryption (existing code)
            salt = self._generate_salt()
            key = self._derive_key(password, salt)
            file_nonce = secrets.token_bytes(12)
            
            # Prepare metadata
            metadata = {
                "version": 1,
                "encryption_method": "password",
                "salt": base64.b64encode(salt).decode(),
                "nonce": base64.b64encode(file_nonce).decode(),
                "integrity_hash": base64.b64encode(file_hash).decode(),
                "original_filename": original_filename,
                "compress": True
            }
        else:
            # Public key encryption
            # Generate a random AES key
            aes_key = secrets.token_bytes(32)  # 256-bit key
            file_nonce = secrets.token_bytes(12)
            
            # Load the recipient's public key
            trusted_key_path = trusted_key["path"]
            with open(trusted_key_path, 'rb') as f:
                public_key_data = f.read()
            
            public_key = load_pem_public_key(public_key_data)
            
            # Encrypt the AES key with recipient's public key
            encrypted_key = public_key.encrypt(
                aes_key,
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Prepare metadata
            metadata = {
                "version": 1,
                "encryption_method": "public_key",
                "encrypted_key": base64.b64encode(encrypted_key).decode(),
                "nonce": base64.b64encode(file_nonce).decode(),
                "integrity_hash": base64.b64encode(file_hash).decode(),
                "original_filename": original_filename,
                "recipient": trusted_key.get("alias", "unknown"),
                "compress": True
            }
            
            # Use the randomly generated AES key directly
            key = aes_key

        # Write the file with metadata header and encrypted chunks
        with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            # Write metadata header
            metadata_bytes = json.dumps(metadata).encode()
            outfile.write(len(metadata_bytes).to_bytes(4, 'big'))
            outfile.write(metadata_bytes)
            
            # Process file in chunks
            chunk_position = 0  # Track position for nonce generation
            while True:
                # Save position before reading for consistent nonce generation
                current_position = chunk_position
                
                # Read chunk and increment position counter
                chunk = infile.read(self.CHUNK_SIZE)
                if not chunk:
                    break
                
                chunk_position += len(chunk)
                    
                # Encrypt chunk with unique nonce derived from file_nonce and chunk position
                chunk_nonce = self._hash_data(file_nonce + current_position.to_bytes(8, 'big'))[:12]
                encrypted_chunk = self._encrypt_chunk(key, chunk, chunk_nonce)
                
                # Write encrypted chunk length and data
                chunk_len_bytes = len(encrypted_chunk).to_bytes(4, 'big')
                outfile.write(chunk_len_bytes)
                outfile.write(encrypted_chunk)

    def decrypt_file(self, input_path: str, output_path: Optional[str] = None, 
                     password: str = "") -> bool:
        """
        Decrypt a file using authenticated decryption
        
        Args:
            input_path: Path to encrypted file
            output_path: Optional path to save decrypted file
            password: Decryption password (optional if using private key)
        
        Returns:
            Boolean indicating success
        """
        with open(input_path, 'rb') as infile:
            # Read and parse metadata
            metadata_length = int.from_bytes(infile.read(4), 'big')
            metadata_bytes = infile.read(metadata_length)
            
            try:
                metadata = json.loads(metadata_bytes.decode('utf-8'))
            except UnicodeDecodeError as e:
                raise ValueError("Invalid file format or corrupted metadata") from e
            
            # Extract encryption method
            encryption_method = metadata.get("encryption_method", "password")
            
            if encryption_method == "password":
                # Password-based decryption (existing code)
                salt = base64.b64decode(metadata["salt"])
                file_nonce = base64.b64decode(metadata["nonce"])
                key = self._derive_key(password, salt)
            else:
                # Public key decryption
                encrypted_key = base64.b64decode(metadata["encrypted_key"])
                file_nonce = base64.b64decode(metadata["nonce"])
                
                # Load our private key
                with open(self.private_key_path, 'rb') as f:
                    private_key_data = f.read()
                
                try:
                    private_key = load_pem_private_key(private_key_data, None)
                    
                    # Decrypt the AES key
                    key = private_key.decrypt(
                        encrypted_key,
                        asymmetric_padding.OAEP(
                            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                except Exception as e:
                    raise ValueError("Decryption failed - you may not be the intended recipient") from e
            
            # Extract original filename
            original_filename = metadata.get("original_filename", "decrypted_file.bin")
            
            # Determine output path - always use original filename in same directory as input
            input_dir = os.path.dirname(input_path)
            if not output_path:
                output_path = os.path.join(input_dir, original_filename)
            
            # Make sure we have a unique filename
            final_output_path = self.get_unique_filename(output_path)
            print(f"Will save as: {final_output_path}")
            
            # Create a temporary file for decryption to avoid creating corrupted files
            # Use a more reliable approach for temporary file handling
            temp_output_path = None
            outfile = None
            try:
                # Create temporary file with a unique name in the same directory
                temp_fd, temp_output_path = tempfile.mkstemp(prefix="decrypt_", suffix=".tmp", dir=input_dir)
                # Close the file descriptor separately from the file object
                os.close(temp_fd)
                
                # Open with explicit context manager for proper cleanup
                with open(temp_output_path, 'wb') as outfile:
                    # Process encrypted chunks into the temporary file
                    while True:
                        # Read chunk length
                        chunk_length_bytes = infile.read(4)
                        if not chunk_length_bytes or len(chunk_length_bytes) < 4:
                            break
                        
                        chunk_length = int.from_bytes(chunk_length_bytes, 'big')
                        encrypted_chunk = infile.read(chunk_length)
                        
                        # Get position for nonce generation
                        current_position = outfile.tell()
                        
                        # Decrypt chunk
                        chunk_nonce = self._hash_data(file_nonce + current_position.to_bytes(8, 'big'))[:12]
                        try:
                            decrypted_chunk = self._decrypt_chunk(key, encrypted_chunk, chunk_nonce)
                        except InvalidTag as e:
                            # Let the outer exception handler clean up the temporary file
                            raise ValueError("Decryption failed - incorrect password or corrupted file") from e
                        
                        outfile.write(decrypted_chunk)
                
                # Everything was successful, move the temporary file to its final destination
                # Make sure we close all file handles first and handle Windows file behavior
                try:
                    # Check if the output file already exists
                    if os.path.exists(final_output_path):
                        # Try to remove it first, with retry logic
                        try:
                            os.unlink(final_output_path)
                        except PermissionError:
                            # If we can't delete it directly, try renaming it first (Windows workaround)
                            backup_path = final_output_path + ".bak"
                            if os.path.exists(backup_path):
                                os.unlink(backup_path)
                            os.rename(final_output_path, backup_path)
                            os.unlink(backup_path)
                    
                    # Now move the temporary file to the final destination
                    os.rename(temp_output_path, final_output_path)
                    # Successfully moved, set temp_output_path to None so we don't try to delete it
                    temp_output_path = None
                    
                except (OSError, PermissionError):
                    # If rename fails, try copy + delete approach
                    import shutil
                    shutil.copy2(temp_output_path, final_output_path)
                    os.unlink(temp_output_path)
                    temp_output_path = None
                
                return True
                
            except Exception as e:
                # Re-raise the original error
                raise e
            finally:
                # Clean up the temporary file if it still exists
                if temp_output_path and os.path.exists(temp_output_path):
                    try:
                        os.unlink(temp_output_path)
                    except (OSError, FileNotFoundError, PermissionError):
                        pass  # Ignore errors during cleanup
    
    def load_key_from_file(self, key_path: str) -> bytes:
        """Load a key from file"""
        with open(key_path, 'rb') as f:
            return f.read()
    
    def get_default_keypair(self) -> Tuple[bytes, bytes]:
        """
        Get the default keypair, generating it if it doesn't exist
        
        Returns:
            Tuple of (private_key_pem, public_key_pem)
        """
        # Check if keys already exist
        if os.path.exists(self.private_key_path) and os.path.exists(self.public_key_path):
            with open(self.private_key_path, 'rb') as f:
                private_key_pem = f.read()
            with open(self.public_key_path, 'rb') as f:
                public_key_pem = f.read()
            return private_key_pem, public_key_pem
        
        # Generate new keys
        print("Generating new default keypair...")
        keymanger = KeyManager()
        private_key_pem, public_key_pem = keymanger.generate_keypair(self.keys_dir)
        return private_key_pem, public_key_pem
    
    def get_unique_filename(self, file_path: str) -> str:
        """
        Get a unique filename if the original one exists
        by appending a number to it
        
        Args:
            file_path: Original file path
            
        Returns:
            Unique file path that doesn't exist
        """
        if not os.path.exists(file_path):
            return file_path
            
        base_dir = os.path.dirname(file_path)
        filename, extension = os.path.splitext(os.path.basename(file_path))
        
        counter = 1
        while True:
            new_path = os.path.join(base_dir, f"{filename}_{counter}{extension}")
            if not os.path.exists(new_path):
                return new_path
            counter += 1
    
    def encrypt_directory(self, directory: Union[str, Path], password=None, trusted_key=None) -> None:
        """
        Encrypt entire directory as a single encrypted archive with multithreading
        
        Args:
            directory: Directory path to encrypt
            password: Optional encryption password
            trusted_key: Optional trusted key info for public key encryption
        """
        # Validate that at least one encryption method is provided
        if password is None and trusted_key is None:
            raise ValueError("Either password or trusted key must be provided")
            
        directory = Path(directory)
        if not directory.is_dir():
            raise ValueError("Invalid directory path")
        
        # Use a more standardized filename pattern
        dir_name = directory.name
        encrypted_path = directory.parent / f"{dir_name}_encrypted.sfc"
        
        # Create temporary archive file
        with tempfile.NamedTemporaryFile(suffix='.sfa', delete=False) as temp_archive:
            temp_path = temp_archive.name
            temp_archive.close()  # Close immediately to avoid issues on Windows
            
            try:
                # Archive the directory using our custom archiver
                print(f"Creating archive of directory: {directory}")
                with open(temp_path, 'wb') as archive_file:
                    metadata = self.archiver.archive_directory(
                        directory, 
                        archive_file,
                        compression_level=6  # Medium compression
                    )
                
                # Get archive info for display
                file_count = metadata['file_count']
                dir_count = metadata['dir_count']
                total_size = metadata['total_size']
                print(f"Archive created with {file_count} files and {dir_count} directories")
                print(f"Original size: {total_size/1024:.1f} KB")
                
                # Encrypt the archive
                print("Encrypting archive...")
                from rich.progress import BarColumn, Progress, TextColumn, TimeRemainingColumn
                
                with Progress(
                    TextColumn("[bold cyan]Encrypting archive...[/bold cyan]"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.1f}%"),
                    TimeRemainingColumn()
                ) as progress:
                    task = progress.add_task("Encrypting...", total=100)
                    
                    # Update progress to 10% to show we're starting
                    progress.update(task, completed=10)
                    
                    # Custom encryption for directory archive with proper content_type
                    if trusted_key:
                        # Generate a random AES key for public key encryption
                        aes_key = secrets.token_bytes(32)  # 256-bit key
                        file_nonce = secrets.token_bytes(12)
                        file_hash = self._calculate_file_hash(temp_path)
                        
                        # Load the recipient's public key
                        trusted_key_path = trusted_key["path"]
                        with open(trusted_key_path, 'rb') as f:
                            public_key_data = f.read()
                        
                        public_key = load_pem_public_key(public_key_data)
                        
                        # Encrypt the AES key with recipient's public key
                        encrypted_key = public_key.encrypt(
                            aes_key,
                            asymmetric_padding.OAEP(
                                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        
                        # Prepare metadata with directory content type
                        metadata = {
                            "version": 1,
                            "encryption_method": "public_key",
                            "encrypted_key": base64.b64encode(encrypted_key).decode(),
                            "nonce": base64.b64encode(file_nonce).decode(),
                            "integrity_hash": base64.b64encode(file_hash).decode(),
                            "original_filename": f"{dir_name}.sfa",
                            "recipient": trusted_key.get("alias", "unknown"),
                            "compress": True,
                            "content_type": "directory"  # Important flag
                        }
                        
                        key = aes_key
                    else:
                        # Password-based encryption
                        salt = self._generate_salt()
                        key = self._derive_key(password, salt)
                        file_nonce = secrets.token_bytes(12)
                        file_hash = self._calculate_file_hash(temp_path)
                        
                        # Prepare metadata with directory content type
                        metadata = {
                            "version": 1,
                            "encryption_method": "password",
                            "salt": base64.b64encode(salt).decode(),
                            "nonce": base64.b64encode(file_nonce).decode(),
                            "integrity_hash": base64.b64encode(file_hash).decode(),
                            "original_filename": f"{dir_name}.sfa",
                            "compress": True,
                            "content_type": "directory"  # Important flag
                        }
                    
                    # Write encrypted file with custom metadata
                    with open(temp_path, 'rb') as infile, open(str(encrypted_path), 'wb') as outfile:
                        # Write metadata header
                        metadata_bytes = json.dumps(metadata).encode()
                        outfile.write(len(metadata_bytes).to_bytes(4, 'big'))
                        outfile.write(metadata_bytes)
                        
                        # Process file in chunks
                        chunk_position = 0
                        while True:
                            # Read chunk and increment position counter
                            chunk = infile.read(self.CHUNK_SIZE)
                            if not chunk:
                                break
                            
                            # Save position before reading for consistent nonce generation
                            current_position = chunk_position
                            chunk_position += len(chunk)
                                
                            # Encrypt chunk with unique nonce derived from file_nonce and chunk position
                            chunk_nonce = self._hash_data(file_nonce + current_position.to_bytes(8, 'big'))[:12]
                            encrypted_chunk = self._encrypt_chunk(key, chunk, chunk_nonce)
                            
                            # Write encrypted chunk length and data
                            chunk_len_bytes = len(encrypted_chunk).to_bytes(4, 'big')
                            outfile.write(chunk_len_bytes)
                            outfile.write(encrypted_chunk)
                        
                        # Update progress
                        progress.update(task, completed=100)
                
                print("Directory archived and encrypted successfully!")
                print(f"Saved to: {encrypted_path}")
                
            finally:
                # Clean up temporary file
                try:
                    if os.path.exists(temp_path):
                        os.unlink(temp_path)
                except OSError as e:
                    print(f"Warning: Could not delete temporary archive: {e}")

    def decrypt_directory(
            self,
            encrypted_path: Union[str, Path], 
            password: str, 
            output_dir: Optional[str] = None) -> None:
        """
        Decrypt an encrypted directory archive
        
        Args:
            encrypted_path: Path to encrypted directory archive
            password: Decryption password
            output_dir: Optional output directory path (will auto-generate if None)
        """
        encrypted_path = Path(encrypted_path)
        if not encrypted_path.is_file():
            raise ValueError("Invalid encrypted file path")
        
        # Auto-generate output directory if not specified
        if output_dir is None:    
            output_dir = encrypted_path.parent / encrypted_path.stem.replace('_encrypted', '')
        else:
            output_dir = Path(output_dir)
        
        # Check file size to detect large archives and adjust behavior accordingly
        file_size = os.path.getsize(encrypted_path)
        is_large_archive = file_size > 500 * 1024 * 1024  # > 500MB
        
        # For large archives, use more robust temporary file handling
        if is_large_archive:
            print(f"Detected large archive ({file_size / (1024*1024):.1f} MB). Using enhanced handling mode.")
            
        # Create a better temporary path in user's directory instead of system temp
        temp_dir = encrypted_path.parent
        temp_file_id = f"temp_decrypted_{int(time.time())}_{secrets.token_hex(4)}"
        temp_dec_path = os.path.join(temp_dir, f"{temp_file_id}.sfa")
        
        try:
            print("Starting decryption of directory archive...")
            
            # Decrypt the file 
            if is_large_archive:
                # For large files, use special decrypt mode with additional verification
                success = self._decrypt_large_file(str(encrypted_path), temp_dec_path, password)
                if not success:
                    raise ValueError("Large file decryption failed. The password may be incorrect.")
            else:
                # Standard decryption for smaller files
                self.decrypt_file(str(encrypted_path), temp_dec_path, password)
            
            # Ensure the file exists and has content
            if not os.path.exists(temp_dec_path):
                raise ValueError(f"Failed to create temporary file: {temp_dec_path}")
                
            file_size = os.path.getsize(temp_dec_path)
            if file_size == 0:
                raise ValueError("Decryption produced an empty file")
            
            print(f"Decrypted archive file size: {file_size} bytes")
            
            # Verify it's a valid archive
            if not self.archiver.is_valid_archive(temp_dec_path):
                raise ValueError("Decryption produced an invalid archive. Password may be incorrect.")
            
            # Create the output directory if it doesn't exist
            output_dir.mkdir(exist_ok=True, parents=True)
            
            # Extract the archive
            print(f"Extracting archive to {output_dir}...")
            with open(temp_dec_path, 'rb') as archive_file:
                metadata = self.archiver.extract_directory(archive_file, output_dir)
            
            # Show extraction results
            print("Directory decrypted and extracted successfully!")
            print(f"Extracted {metadata['file_count']} files and {metadata['dir_count']} directories")
                
        except ValueError as e:
            # Re-raise ValueError directly
            raise e
        except Exception as e:
            # Clean up the output directory if decryption fails and it's empty
            if output_dir.exists():
                try:
                    if not os.listdir(output_dir):
                        os.rmdir(output_dir)
                    else:
                        # If there are files but extraction failed, it might be partial
                        import shutil
                        shutil.rmtree(output_dir, ignore_errors=True)
                except Exception:
                    pass
            raise ValueError(f"Directory decryption failed: {str(e)}") from e
        finally:
            # Clean up temporary file with retry logic
            self._delete_temp_file_with_retry(temp_dec_path)

    def _delete_temp_file_with_retry(self, file_path: str, max_retries: int = 5) -> None:
        """
        Delete a temporary file with retry logic to handle Windows file locks
        
        Args:
            file_path: Path to the file to delete
            max_retries: Maximum number of retries
        """
        if not os.path.exists(file_path):
            return
            
        for attempt in range(max_retries):
            try:
                os.unlink(file_path)
                print(f"Temporary file {file_path} deleted")
                return
            except (OSError, PermissionError) as e:
                if attempt < max_retries - 1:
                    print(f"Couldn't delete temp file (attempt {attempt+1}), retrying in 1 second: {e}")
                    time.sleep(1)  # Wait before retry
                else:
                    print(f"Warning: Could not delete temporary file after {max_retries} attempts: {e}")
                    
                    # On Windows, try an alternative approach for locked files
                    import platform
                    if platform.system() == 'Windows':
                        try:
                            # Create a bat script to delete the file later
                            delete_script = os.path.join(os.path.dirname(file_path), "delete_temp.bat")
                            with open(delete_script, 'w') as f:
                                f.write("@echo off\n")
                                f.write("timeout /t 5 /nobreak > nul\n")  # Wait 5 seconds
                                f.write(f"del \"{file_path}\"\n")
                                f.write("del \"%~f0\"\n")  # Self-delete the bat file
                            
                            # Execute the script
                            os.startfile(delete_script)
                            print(f"Scheduled delayed deletion of {file_path}")
                        except Exception as script_error:
                            print(f"Note: Cleanup script creation failed: {script_error}")

    def _calculate_file_hash(self, file_path: str) -> bytes:
        """Calculate a hash of the entire file for integrity checking"""
        hasher = hashes.Hash(hashes.SHA256())
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(self.CHUNK_SIZE):
                hasher.update(chunk)
                
        return hasher.finalize()

    def _encrypt_file_multithreaded(self, input_path: str, output_path: str, password: str) -> None:
        """
        Encrypt a file using authenticated encryption with multithreading for large files
        
        Args:
            input_path: Path to file to encrypt
            output_path: Path to save encrypted file
            password: Encryption password
        """
        # Check if the file is large enough to benefit from multithreading
        file_size = os.path.getsize(input_path)
        use_threading = file_size > 50 * 1024 * 1024  # Only for files > 50MB
        
        if use_threading:
            self._encrypt_file_parallel(input_path, output_path, password)
        else:
            # Use standard encryption for smaller files
            self.encrypt_file(input_path, output_path, password)

    def _encrypt_file_parallel(self, input_path: str, output_path: str, password: str) -> None:
        """
        Encrypt a file using parallel processing for improved performance
        
        Args:
            input_path: Path to file to encrypt
            output_path: Path to save encrypted file
            password: Encryption password
        """
        # Same setup as regular encrypt_file
        file_hash = self._calculate_file_hash(input_path)
        original_filename = os.path.basename(input_path)
        salt = self._generate_salt()
        key = self._derive_key(password, salt)
        file_nonce = secrets.token_bytes(12)  # 96-bit nonce for AES-GCM
        
        # Prepare metadata
        metadata = {
            "version": 1,
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(file_nonce).decode(),
            "integrity_hash": base64.b64encode(file_hash).decode(),
            "original_filename": original_filename,  # Store original filename
            "compress": True,
            "multithreaded": True  # Flag that we used multithreading
        }
        
        # Determine optimal chunk size and number of threads
        file_size = os.path.getsize(input_path)
        optimal_chunks = thread_pool.get_optimal_thread_count(io_bound=True)
        chunk_size = max(self.CHUNK_SIZE, file_size // optimal_chunks)
        
        # Pre-calculate chunk information
        chunks_info = []
        with open(input_path, 'rb') as infile:
            position = 0
            chunk_id = 0
            while True:
                chunk = infile.read(chunk_size)
                if not chunk:
                    break
                chunks_info.append({
                    'id': chunk_id,
                    'position': position,
                    'size': len(chunk),
                    'offset': 0  # To be set later
                })
                position += len(chunk)
                chunk_id += 1
        
        # Function to process a single chunk
        def encrypt_chunk(chunk_info):
            chunk_id = chunk_info['id']
            chunk_position = chunk_info['position']
            
            # Read the chunk
            with open(input_path, 'rb') as infile:
                infile.seek(chunk_position)
                chunk = infile.read(chunk_info['size'])
                
            # Generate a unique nonce for this chunk
            chunk_nonce = self._hash_data(file_nonce + chunk_id.to_bytes(8, 'big'))[:12]
            
            # Encrypt the chunk
            encrypted_chunk = self._encrypt_chunk(key, chunk, chunk_nonce)
            
            return {
                'id': chunk_id,
                'encrypted': encrypted_chunk
            }
        
        # Encrypt all chunks in parallel
        print(f"Encrypting file with {len(chunks_info)} chunks using "
              f"{optimal_chunks} parallel threads...")
        encrypted_chunks = thread_pool.parallel_map(encrypt_chunk, chunks_info, io_bound=False)
        
        # Sort by chunk ID to maintain order
        encrypted_chunks.sort(key=lambda x: x['id'])
        
        # Write all data to output file
        with open(output_path, 'wb') as outfile:
            # Write metadata header
            metadata_bytes = json.dumps(metadata).encode()
            outfile.write(len(metadata_bytes).to_bytes(4, 'big'))
            outfile.write(metadata_bytes)
            
            # Write each encrypted chunk
            for chunk in encrypted_chunks:
                encrypted_data = chunk['encrypted']
                chunk_len_bytes = len(encrypted_data).to_bytes(4, 'big')
                outfile.write(chunk_len_bytes)
                outfile.write(encrypted_data)

    def _decrypt_large_file(self, input_path: str, output_path: str, password: str) -> bool:
        """
        Special decryption method for large files with enhanced error handling
        
        Args:
            input_path: Path to encrypted file
            output_path: Path to save decrypted file 
            password: Password for decryption
            
        Returns:
            Boolean indicating successful decryption
        """
        try:
            with open(input_path, 'rb') as infile:
                # Read and parse metadata
                metadata_length = int.from_bytes(infile.read(4), 'big')
                if metadata_length <= 0 or metadata_length > 10_000_000:  # Sanity check
                    return False
                    
                metadata_bytes = infile.read(metadata_length)
                
                try:
                    metadata = json.loads(metadata_bytes.decode('utf-8'))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    return False
                
                version = metadata.get("version", 1)
                if version > 1:
                    return False
                    
                # Extract encryption materials
                salt = base64.b64decode(metadata.get("salt", ""))
                file_nonce = base64.b64decode(metadata.get("nonce", ""))
                if not salt or not file_nonce:
                    return False
                    
                key = self._derive_key(password, salt)
                
                # Create output file
                with open(output_path, 'wb') as outfile:
                    # Process encrypted chunks with careful error handling
                    chunk_position = 0
                    multithreaded = metadata.get("multithreaded", False)
                    
                    while True:
                        # Read chunk length
                        chunk_length_bytes = infile.read(4)
                        if not chunk_length_bytes or len(chunk_length_bytes) < 4:
                            break
                        
                        chunk_length = int.from_bytes(chunk_length_bytes, 'big')
                        if chunk_length <= 0 or chunk_length > 1_000_000_000:  # Sanity check: 1GB max chunk
                            return False
                            
                        encrypted_chunk = infile.read(chunk_length)
                        if len(encrypted_chunk) != chunk_length:
                            return False
                        
                        # Generate chunk nonce
                        if multithreaded:
                            # For multithreaded files, the chunk ID is used
                            chunk_nonce = self._hash_data(file_nonce + chunk_position.to_bytes(8, 'big'))[:12]
                        else:
                            # For standard files, the position is used
                            current_pos = outfile.tell()
                            chunk_nonce = self._hash_data(file_nonce + current_pos.to_bytes(8, 'big'))[:12]
                        
                        # Decrypt chunk
                        try:
                            decrypted_chunk = self._decrypt_chunk(key, encrypted_chunk, chunk_nonce)
                            outfile.write(decrypted_chunk)
                            chunk_position += 1
                        except InvalidTag as e:
                            raise ValueError("Decryption failed - incorrect password or corrupted file") from e
                
                return True
                
        except Exception:
            return False

    def sign_file(self, file_path: str, signature_path: Optional[str] = None) -> str:
        """
        Sign a file with the private key
        
        Args:
            file_path: Path to file to sign
            signature_path: Optional path to save signature file (default: file_path + ".sig")
            
        Returns:
            Path to signature file
        """
        if not os.path.exists(self.private_key_path):
            raise ValueError("No private key found. Generate or import a key first.")
        
        # Default signature path
        if signature_path is None:
            signature_path = f"{file_path}.sig"
            
        # Load private key
        try:
            with open(self.private_key_path, 'rb') as f:
                private_key_data = f.read()
            
            private_key = load_pem_private_key(private_key_data, password=None)
        except Exception as e:
            raise ValueError(f"Failed to load private key: {str(e)}") from e
        
        # Calculate file hash
        file_hash = self._calculate_file_hash(file_path)
        
        # Create signature
        try:
            # Use PSS padding for better security
            signature = private_key.sign(
                file_hash,
                asymmetric_padding.PSS(
                    mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                    salt_length=asymmetric_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except Exception as e:
            raise ValueError(f"Failed to sign file: {str(e)}") from e
        
        # Create signature metadata
        signature_data = {
            "version": 1,
            "algorithm": "RSA-PSS",
            "hash_algorithm": "SHA256",
            "signature": base64.b64encode(signature).decode('utf-8'),
            "file_name": os.path.basename(file_path),
            "created_at": time.time(),
            "signature_type": "file"
        }
        
        # Write signature to file
        with open(signature_path, 'w') as f:
            json.dump(signature_data, f, indent=2)
            
        return signature_path

    def verify_signature(
            self,
            file_path: str,
            signature_path: str,
            public_key_path: Optional[str] = None
            ) -> Tuple[bool, Dict[str, Any]]:
        """
        Verify a file's signature
        
        Args:
            file_path: Path to file to verify
            signature_path: Path to signature file
            public_key_path: Optional path to public key (default: use own public key)
            
        Returns:
            Tuple of (is_valid, signature_info)
        """
        if not os.path.exists(file_path):
            raise ValueError(f"File not found: {file_path}")
        
        if not os.path.exists(signature_path):
            raise ValueError(f"Signature file not found: {signature_path}")
        
        # Determine which public key to use
        if public_key_path is None:
            if not os.path.exists(self.public_key_path):
                raise ValueError("No public key found. Generate or import a key first.")
            public_key_path = self.public_key_path
        
        # Load public key
        try:
            with open(public_key_path, 'rb') as f:
                public_key_data = f.read()
            
            public_key = load_pem_public_key(public_key_data)
        except Exception as e:
            raise ValueError(f"Failed to load public key: {str(e)}") from e
        
        # Load signature
        try:
            with open(signature_path, 'r') as f:
                signature_data = json.load(f)
                
            signature = base64.b64decode(signature_data["signature"])
            signature_file_name = signature_data.get("file_name")
            
            # Optional validation that signature is for this file
            if signature_file_name and os.path.basename(file_path) != signature_file_name:
                print(f"Warning: Signature was created for '{signature_file_name}' "
                      f"but verifying '{os.path.basename(file_path)}'")
        except Exception as e:
            raise ValueError(f"Failed to load signature: {str(e)}") from e
        
        # Calculate file hash
        file_hash = self._calculate_file_hash(file_path)
        
        # Verify signature
        try:
            public_key.verify(
                signature,
                file_hash,
                asymmetric_padding.PSS(
                    mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                    salt_length=asymmetric_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            # If no exception is raised, verification succeeded
            return True, signature_data
        except InvalidSignature:
            return False, signature_data
        except Exception as e:
            raise ValueError(f"Verification error: {str(e)}") from e

    def sign_data(self, data: bytes) -> bytes:
        """
        Sign arbitrary data with the private key
        
        Args:
            data: Bytes to sign
            
        Returns:
            Signature bytes
        """
        if not os.path.exists(self.private_key_path):
            raise ValueError("No private key found. Generate or import a key first.")
        
        # Load private key
        try:
            with open(self.private_key_path, 'rb') as f:
                private_key_data = f.read()
            
            private_key = load_pem_private_key(private_key_data, password=None)
        except Exception as e:
            raise ValueError(f"Failed to load private key: {str(e)}") from e
        
        # Create hash of data
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        data_hash = digest.finalize()
        
        # Create signature
        try:
            signature = private_key.sign(
                data_hash,
                asymmetric_padding.PSS(
                    mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                    salt_length=asymmetric_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return signature
        except Exception as e:
            raise ValueError(f"Failed to sign data: {str(e)}") from e

    def verify_data_signature(self, data: bytes, signature: bytes, public_key_path: Optional[str] = None) -> bool:
        """
        Verify signature of arbitrary data
        
        Args:
            data: Bytes to verify
            signature: Signature bytes
            public_key_path: Optional path to public key (default: use own public key)
            
        Returns:
            True if signature is valid
        """
        # Determine which public key to use
        if public_key_path is None:
            if not os.path.exists(self.public_key_path):
                raise ValueError("No public key found. Generate or import a key first.")
            public_key_path = self.public_key_path
        
        # Load public key
        try:
            with open(public_key_path, 'rb') as f:
                public_key_data = f.read()
            
            public_key = load_pem_public_key(public_key_data)
        except Exception as e:
            raise ValueError(f"Failed to load public key: {str(e)}") from e
        
        # Create hash of data
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        data_hash = digest.finalize()
        
        # Verify signature
        try:
            public_key.verify(
                signature,
                data_hash,
                asymmetric_padding.PSS(
                    mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                    salt_length=asymmetric_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            # If no exception is raised, verification succeeded
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            raise ValueError(f"Verification error: {str(e)}") from e