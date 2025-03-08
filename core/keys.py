"""
Key Management Utilities for FileCrypter

This module provides utilities for managing cryptographic keys,
including key generation, import, export, and validation.
"""

import datetime
import json
import os
import re
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)


class KeyManager:
    """Utility class for managing cryptographic keys"""
    
    def __init__(self, base_dir: Optional[str] = None):
        """
        Initialize KeyManager
        
        Args:
            base_dir: Base directory for keys. If None, use default location.
        """
        if base_dir:
            self.base_dir = Path(base_dir)
        else:
            self.base_dir = Path(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "keys")))
        
        # Set up directory structure
        self.keys_dir = self.base_dir
        self.trust_dir = self.keys_dir / "trusted"
        self.revoked_dir = self.keys_dir / "revoked"
        
        # Create directories if they don't exist
        self.keys_dir.mkdir(exist_ok=True, parents=True)
        self.trust_dir.mkdir(exist_ok=True, parents=True)
        self.revoked_dir.mkdir(exist_ok=True, parents=True)
        
        # Define key paths
        self.private_key_path = self.keys_dir / "private_key.pem"
        self.public_key_path = self.keys_dir / "public_key.pem"
        self.trusted_keys_index = self.trust_dir / "trusted_keys.json"
        
        # Initialize the trusted keys index if it doesn't exist
        if not self.trusted_keys_index.exists():
            self._write_trusted_keys_index({})
    
    def generate_keypair(self, save_path: Optional[str] = None) -> Tuple[bytes, bytes]:
        """
        Generate RSA keypair for future use
        
        Args:
            save_path: Optional directory to save keys to files
            
        Returns:
            Tuple of (private_key_pem, public_key_pem)
        """
        # Generate a 3072-bit RSA key (good security through 2030+)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072
        )
        public_key = private_key.public_key()
        
        # Serialize keys to PEM format
        private_key_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        )
        
        public_key_pem = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )
        
        # Save keys to files if path provided
        if save_path:
            save_dir = Path(save_path)
            save_dir.mkdir(exist_ok=True, parents=True)
            
            private_key_file = save_dir / "private_key.pem"
            public_key_file = save_dir / "public_key.pem"
            
            private_key_file.write_bytes(private_key_pem)
            public_key_file.write_bytes(public_key_pem)
            
            # Set restrictive permissions for private key
            try:
                os.chmod(private_key_file, 0o600)  # Read/write for owner only
            except OSError:
                # Permissions might not be supported on some platforms
                pass
                
            print(f"Keys saved to {save_dir}")
        
        return private_key_pem, public_key_pem
        
    def import_public_key(self, key_path: str, alias: str) -> str:
        """
        Import someone's public key
        
        Args:
            key_path: Path to public key file
            alias: Name/alias for this key
            
        Returns:
            Path to imported key file
        """
        # Validate the key first
        try:
            with open(key_path, 'rb') as f:
                key_data = f.read()
                
            public_key = load_pem_public_key(key_data)
                
            # Simple validation: make sure it has the right methods
            if not hasattr(public_key, 'encrypt'):
                raise ValueError("Not a valid public key")
                
            # Get key fingerprint (SHA-256 hash of public key bytes)
            key_fingerprint = self._calculate_key_fingerprint(key_data)
            
            # Check if this key is already in our trusted keys
            existing_keys = self._read_trusted_keys_index()
            for existing_alias, existing_info in existing_keys.items():
                if existing_info.get("fingerprint") == key_fingerprint:
                    raise ValueError(f"This key is already imported with alias '{existing_alias}'")
                
        except Exception as e:
            raise ValueError(f"Invalid public key: {str(e)}") from e
            
        # Sanitize alias for filename use
        safe_alias = re.sub(r'[^\w.-]', '_', alias)
        
        # Create target path
        target_path = self.trust_dir / f"{safe_alias}.pem"
        
        # Copy the key file
        shutil.copy2(key_path, target_path)
        
        # Add to trusted keys index
        keys_data = self._read_trusted_keys_index()
        keys_data[safe_alias] = {
            "path": str(target_path),
            "alias": alias,
            "imported_at": datetime.datetime.now().isoformat(),
            "filename": os.path.basename(key_path),
            "fingerprint": key_fingerprint
        }
        self._write_trusted_keys_index(keys_data)
        
        return str(target_path)
   
    def export_public_key(self, output_path: str) -> str:
        """
        Export your public key to share with others
        
        Args:
            output_path: Path to save the public key
            
        Returns:
            Path to exported key file
        """
        # Make sure we have a public key to export
        if not self.public_key_path.exists():
            # Generate a new keypair first
            self.generate_keypair(self.keys_dir)
            
        # Copy the public key to the specified location
        shutil.copy2(self.public_key_path, output_path)
        
        return output_path
        
    def get_trusted_keys(self) -> Dict:
        """Get list of trusted public keys"""
        return self._read_trusted_keys_index()
        
    def delete_trusted_key(self, alias: str) -> bool:
        """
        Remove a trusted key
        
        Args:
            alias: Alias of the key to remove
            
        Returns:
            True if successful
        """
        keys_data = self._read_trusted_keys_index()
        
        if alias not in keys_data:
            return False
            
        # Get the key path
        key_path = keys_data[alias].get("path")
        
        # Delete the key file
        if key_path and os.path.exists(key_path):
            try:
                os.unlink(key_path)
            except OSError:
                pass
                
        # Remove from index
        del keys_data[alias]
        self._write_trusted_keys_index(keys_data)
        
        return True
        
    def get_trusted_key_path(self, alias: str) -> Optional[str]:
        """
        Get the path to a trusted key by alias
        
        Args:
            alias: Alias of the key
            
        Returns:
            Path to the key file, or None if not found
        """
        keys_data = self._read_trusted_keys_index()
        
        if alias in keys_data:
            return keys_data[alias].get("path")
            
        return None
        
    def revoke_key(self, alias: str) -> bool:
        """
        Revoke a trusted key (move to revoked directory)
        
        Args:
            alias: Alias of the key to revoke
            
        Returns:
            True if successful
        """
        keys_data = self._read_trusted_keys_index()
        
        if alias not in keys_data:
            return False
            
        # Get the key info
        key_info = keys_data[alias]
        key_path = key_info.get("path")
        
        if not key_path or not os.path.exists(key_path):
            # Key file doesn't exist, just remove from index
            del keys_data[alias]
            self._write_trusted_keys_index(keys_data)
            return True
        
        # Move the key file to revoked directory
        revoked_path = self.revoked_dir / f"{alias}-revoked-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.pem"
        shutil.move(key_path, revoked_path)
        
        # Remove from trusted keys index
        del keys_data[alias]
        self._write_trusted_keys_index(keys_data)
        
        return True
        
    def get_key_fingerprint(self, key_path: str) -> str:
        """
        Get a fingerprint (hash) of a key for identification and verification
        
        Args:
            key_path: Path to key file
            
        Returns:
            Hex string fingerprint
        """
        with open(key_path, 'rb') as f:
            key_data = f.read()
            
        return self._calculate_key_fingerprint(key_data)
        
    def _calculate_key_fingerprint(self, key_data: bytes) -> str:
        """Calculate a fingerprint for a key"""
        digest = hashes.Hash(hashes.SHA256())
        digest.update(key_data)
        fingerprint_bytes = digest.finalize()
        
        # Format as colon-separated hex pairs
        hex_pairs = []
        for i in range(0, 8):  # Use first 8 bytes for brevity
            hex_pairs.append(fingerprint_bytes[i:i+1].hex())
        return ":".join(hex_pairs)
        
    def _write_trusted_keys_index(self, keys_data: Dict) -> None:
        """Write the trusted keys index file"""
        with open(self.trusted_keys_index, 'w') as f:
            json.dump(keys_data, f, indent=2)
            
    def _read_trusted_keys_index(self) -> Dict:
        """Read the trusted keys index file"""
        if not self.trusted_keys_index.exists():
            return {}
            
        with open(self.trusted_keys_index, 'r') as f:
            return json.load(f)
    
    def verify_key(self, key_path: str) -> Tuple[bool, str]:
        """
        Verify that a key file contains a valid key
        
        Args:
            key_path: Path to key file
            
        Returns:
            Tuple of (is_valid, key_type)
            where key_type is 'public', 'private', or 'unknown'
        """
        try:
            with open(key_path, 'rb') as f:
                key_data = f.read()
                
            # Try loading as public key
            try:
                public_key = load_pem_public_key(key_data)
                if hasattr(public_key, 'encrypt'):
                    return True, 'public'
            except Exception:
                pass
                
            # Try loading as private key
            try:
                private_key = load_pem_private_key(key_data, password=None)
                if hasattr(private_key, 'sign'):
                    return True, 'private'
            except Exception:
                pass
                
            # If we got here, it's not a valid key
            return False, 'unknown'
                
        except Exception:
            return False, 'unknown'
    
    def get_available_keys(self) -> Dict[str, List[Dict]]:
        """
        Get all available keys in the key directories
        
        Returns:
            Dictionary with lists of key info for each type
        """
        result = {
            "private": [],
            "public": [],
            "trusted": [],
            "revoked": []
        }
        
        # Check personal keys
        if self.private_key_path.exists():
            result["private"].append({
                "path": str(self.private_key_path),
                "filename": self.private_key_path.name,
                "type": "private"
            })
            
        if self.public_key_path.exists():
            result["public"].append({
                "path": str(self.public_key_path),
                "filename": self.public_key_path.name,
                "type": "public"
            })
            
        # Add trusted keys
        trusted_keys = self._read_trusted_keys_index()
        for alias, info in trusted_keys.items():
            info["alias"] = alias
            info["type"] = "trusted"
            result["trusted"].append(info)
            
        # Add revoked keys
        for key_file in self.revoked_dir.glob("*.pem"):
            result["revoked"].append({
                "path": str(key_file),
                "filename": key_file.name,
                "type": "revoked"
            })
            
        return result