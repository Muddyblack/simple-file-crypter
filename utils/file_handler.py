"""Utilities for handling files and cleanup tasks"""
import os
import platform
import tempfile
import time
from typing import Tuple


def count_files_in_directory(directory: str) -> Tuple[int, int]:
    """
    Count files and directories in a directory recursively
    
    Args:
        directory: Path to the directory
        
    Returns:
        Tuple of (file_count, dir_count)
    """
    file_count = 0
    dir_count = 0
    
    for _root, dirs, files in os.walk(directory):
        file_count += len(files)
        dir_count += len(dirs)
    
    return file_count, dir_count

def get_safe_temp_file(directory: str, prefix: str = "temp_", suffix: str = ".tmp") -> str:
    """
    Get a safe temporary file path that won't conflict with existing files
    
    Args:
        directory: Directory to create the temp file in
        prefix: Prefix for the filename
        suffix: Suffix (extension) for the filename
        
    Returns:
        Path to the temporary file (file is not created)
    """
    timestamp = int(time.time())
    
    # Try to find a unique filename
    attempt = 0
    while attempt < 100:  # Limit attempts to avoid infinite loop
        temp_name = f"{prefix}{timestamp}_{attempt}{suffix}"
        temp_path = os.path.join(directory, temp_name)
        
        if not os.path.exists(temp_path):
            return temp_path
            
        attempt += 1
    
    # If we get here, use the system's tempfile module
    fd, temp_path = tempfile.mkstemp(suffix=suffix, prefix=prefix, dir=directory)
    os.close(fd)  # Close the file descriptor
    return temp_path

def safe_delete_file(file_path: str, max_retries: int = 3) -> bool:
    """
    Safely delete a file with retry logic
    
    Args:
        file_path: Path to the file to delete
        max_retries: Maximum number of retries
        
    Returns:
        True if the file was deleted, False otherwise
    """
    if not os.path.exists(file_path):
        return True
        
    for attempt in range(max_retries):
        try:
            os.unlink(file_path)
            return True
        except (OSError, PermissionError):
            if attempt < max_retries - 1:
                # Wait before retry
                time.sleep(0.5 * (attempt + 1))
            else:
                # Final attempt failed
                return False
    
    return False

def schedule_file_deletion(file_path: str) -> bool:
    """
    Schedule a file for deletion after the program exits
    Works on different operating systems
    
    Args:
        file_path: Path to the file to delete
        
    Returns:
        True if scheduled, False if couldn't schedule
    """
    if not os.path.exists(file_path):
        return True
        
    try:
        if platform.system() == 'Windows':
            # Create a bat script to delete the file
            script_path = os.path.join(os.path.dirname(file_path), f"delete_{int(time.time())}.bat")
            with open(script_path, 'w') as f:
                f.write("@echo off\n")
                f.write("timeout /t 2 /nobreak > nul\n")  # Wait 2 seconds
                f.write("del \"{file_path}\"\n")
                f.write("if exist \"{file_path}\" (\n")
                f.write("    timeout /t 3 /nobreak > nul\n")
                f.write("    del \"{file_path}\"\n")
                f.write(")\n")
                f.write("del \"%~f0\"\n")  # Self-delete
                
            # Execute the script
            os.startfile(script_path)
            return True
        else:
            # On Unix systems, we can use the at command or similar
            # But for now, just try to delete directly
            return safe_delete_file(file_path)
    except Exception:
        return False

def is_directory_empty(directory: str) -> bool:
    """
    Check if a directory is empty
    
    Args:
        directory: Path to the directory
        
    Returns:
        True if empty, False otherwise
    """
    if not os.path.isdir(directory):
        return False
        
    # Check if there are any files or subdirectories
    return len(os.listdir(directory)) == 0

def clean_empty_dirs(base_dir: str) -> int:
    """
    Remove all empty directories in a directory tree
    
    Args:
        base_dir: Path to the base directory
        
    Returns:
        Number of directories removed
    """
    if not os.path.isdir(base_dir):
        return 0
        
    removed = 0
    for root, dirs, _files in os.walk(base_dir, topdown=False):
        for dir_name in dirs:
            dir_path = os.path.join(root, dir_name)
            if is_directory_empty(dir_path):
                try:
                    os.rmdir(dir_path)
                    removed += 1
                except Exception:
                    pass
                    
    # Check if base directory is now empty
    if base_dir != root and is_directory_empty(base_dir):
        try:
            os.rmdir(base_dir)
            removed += 1
        except Exception:
            pass
            
    return removed
