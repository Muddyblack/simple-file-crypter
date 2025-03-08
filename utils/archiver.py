"""Custom directory archiving utilities with enhanced security"""

import json
import os
import struct
import threading
import time
from pathlib import Path
from typing import BinaryIO, Dict, Union

from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeRemainingColumn

from utils.threading_utils import thread_pool

# File info lock to prevent race conditions when writing to the archive
file_info_lock = threading.Lock()

class DirectoryArchiver:
    """
    A custom directory archiver that creates a single encrypted file from directories.
    Key advantages over ZIP:
    - Custom format makes detection harder
    - No standard signatures that could be identified
    - Simplified structure for better performance
    - Direct integration with encryption
    """
    
    # Format constants
    HEADER_MAGIC = b'SFCDIR01'  # Custom magic bytes, not standard like ZIP's PK header
    BLOCK_SIZE = 1024 * 1024  # 1MB blocks for file data
    
    def archive_directory(self, 
                         directory_path: Union[str, Path], 
                         output_file: BinaryIO,
                         compression_level: int = 6) -> Dict:
        """
        Archive a directory into a custom format stream using parallel processing
        
        Args:
            directory_path: Path to directory to archive
            output_file: File-like object to write archive to
            compression_level: 0-9 compression level (0=none, 9=max)
            
        Returns:
            Dictionary with archive metadata
        """
        directory_path = Path(directory_path)
        if not directory_path.is_dir():
            raise ValueError(f"Not a directory: {directory_path}")
        
        # Start with a fixed header to identify our format
        output_file.write(self.HEADER_MAGIC)
        
        # Gather directory contents
        file_list = []
        dir_list = []
        total_size = 0
        
        # Use rich progress to show scanning progress
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]Scanning directory...[/bold blue]"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn()
        ) as progress:
            scan_task = progress.add_task("Scanning...", total=None)
            
            # Walk directory and collect information
            for root, dirs, files in os.walk(directory_path):
                rel_root = os.path.relpath(root, directory_path.parent)
                
                # Add directories
                for dir_name in dirs:
                    dir_path = os.path.normpath(os.path.join(rel_root, dir_name))
                    dir_list.append(dir_path)
                
                # Add files
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    rel_path = os.path.normpath(os.path.join(rel_root, file_name))
                    
                    try:
                        file_stat = os.stat(file_path)
                        file_info = {
                            'path': rel_path,
                            'size': file_stat.st_size,
                            'mtime': file_stat.st_mtime,
                            'mode': file_stat.st_mode,
                            'offset': 0,  # To be filled in during archive writing
                        }
                        file_list.append((file_path, file_info))
                        total_size += file_stat.st_size
                    except (FileNotFoundError, PermissionError) as e:
                        print(f"Warning: Skipping {file_path}: {e}")
                
                progress.update(scan_task, advance=1)
                
            # Mark scan as complete with accurate count
            progress.update(scan_task, completed=1, total=1)
        
        # Create metadata
        metadata = {
            'original_name': directory_path.name,
            'file_count': len(file_list),
            'dir_count': len(dir_list),
            'total_size': total_size,
            'compression': compression_level > 0,
            'compression_level': compression_level,
            'directories': dir_list,
            'files': [info for _, info in file_list]
        }
        
        # First write a placeholder for the metadata size and offset
        metadata_offset_pos = output_file.tell()
        output_file.write(struct.pack("<Q", 0))  # 8-byte metadata offset placeholder
        
        # Set up queue and offsets for multithreaded compression
        current_offset = output_file.tell()
        output_lock = threading.Lock()
        
        # Update offsets in metadata
        for _, file_info in file_list:
            file_size = file_info['size']
            compressed_size = file_size  # Initial placeholder estimate
            
            # Reserve space in the archive based on estimated size
            with file_info_lock:
                file_info['offset'] = current_offset
                # Add size field size (8 bytes)
                current_offset += 8 + compressed_size
        
        # Process files in parallel using a thread pool
        def process_file(args):
            abs_path, file_info = args
            
            try:
                # If compression enabled, compress here before writing
                if compression_level > 0:
                    import zlib
                    with open(abs_path, 'rb') as src:
                        file_data = src.read()
                    compressed = zlib.compress(file_data, level=compression_level)
                    
                    # Write data to correct position in file
                    with output_lock:
                        output_file.seek(file_info['offset'])
                        output_file.write(struct.pack("<Q", len(compressed)))  # Size of compressed data
                        output_file.write(compressed)
                        
                else:
                    # Without compression, stream directly
                    with output_lock:
                        output_file.seek(file_info['offset'])
                        remaining = file_info['size']
                        output_file.write(struct.pack("<Q", remaining))  # Size of uncompressed data
                        
                        with open(abs_path, 'rb') as src:
                            while remaining > 0:
                                chunk = src.read(min(remaining, self.BLOCK_SIZE))
                                if not chunk:
                                    break
                                output_file.write(chunk)
                                remaining -= len(chunk)
                
                return True
            except Exception as e:
                print(f"Error processing file {abs_path}: {e}")
                return False
        
        # Use a proper Rich progress bar for archiving
        total_files = len(file_list)
        with Progress(
            TextColumn("[bold green]Archiving files...[/bold green]"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.1f}%"),
            TextColumn("({task.completed}/{task.total} files)"),
            TimeRemainingColumn()
        ) as progress:
            archive_task = progress.add_task("Archiving...", total=total_files)
            
            # Process files in batches to avoid memory issues with large directories
            batch_size = 100  # Increased from 50 for better performance
            for i in range(0, len(file_list), batch_size):
                batch = file_list[i:i + batch_size]
                thread_pool.parallel_map(process_file, batch, io_bound=True)
                progress.update(archive_task, advance=len(batch))
        
        # Now write the metadata at the end
        metadata_offset = current_offset
        output_file.seek(current_offset)
        metadata_json = json.dumps(metadata).encode('utf-8')
        output_file.write(metadata_json)
        
        # Go back and update the metadata offset
        output_file.seek(metadata_offset_pos)
        output_file.write(struct.pack("<Q", metadata_offset))
        output_file.seek(0, 2)  # Seek to end
        
        return metadata
    
    def extract_directory(self, 
                         archive_file: BinaryIO, 
                         output_dir: Union[str, Path],
                         validate: bool = True) -> Dict:
        """
        Extract a directory from our custom format archive using parallel processing
        
        Args:
            archive_file: File-like object containing the archive
            output_dir: Directory to extract to
            validate: Whether to validate the archive format
            
        Returns:
            Dictionary with archive metadata
        """
        output_dir = Path(output_dir)
        
        # Read and verify header
        header = archive_file.read(len(self.HEADER_MAGIC))
        if validate and header != self.HEADER_MAGIC:
            raise ValueError("Invalid archive format: header mismatch")
        
        # Read metadata offset
        metadata_offset = struct.unpack("<Q", archive_file.read(8))[0]
        
        # Seek to metadata and read it
        archive_file.seek(metadata_offset)
        metadata_json = archive_file.read()
        metadata = json.loads(metadata_json.decode('utf-8'))
        
        # Create output directory if it doesn't exist
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Get the original name as root directory name
        root_dir_name = metadata.get('original_name', '')
        
        # Create directories in parallel - now with adjusted paths
        def create_directory(dir_path):
            try:
                # Skip the root directory as we're extracting directly to output_dir
                path_parts = Path(dir_path).parts
                if len(path_parts) > 1:  # Has more than just the root part
                    # If the dir path starts with the root dir name, strip it
                    if path_parts[0] == root_dir_name:
                        dir_to_create = output_dir / Path(*path_parts[1:])
                    else:
                        dir_to_create = output_dir / dir_path
                    
                    dir_to_create.mkdir(parents=True, exist_ok=True)
                return True
            except Exception as e:
                print(f"Error creating directory {dir_path}: {e}")
                return False
        
        thread_pool.parallel_for_each(metadata['directories'], create_directory, io_bound=True)
        
        # Extract files in parallel with better locking and error handling
        archive_lock = threading.RLock()  # Use reentrant lock for better safety
        files = metadata['files']
        
        # Determine optimal thread count based on file sizes
        total_size = metadata.get('total_size', 0)
        file_count = len(files)
        
        # For very large archives, limit concurrency to prevent memory issues
        max_workers = thread_pool.get_optimal_thread_count(io_bound=True)
        if total_size > 1024 * 1024 * 1024:  # > 1GB
            max_workers = min(max_workers, 4)  # Limit to 4 threads for large archives
        elif total_size > 500 * 1024 * 1024:  # > 500MB
            max_workers = min(max_workers, 6)  # Limit to 6 threads for medium archives
            
        print(f"Using {max_workers} threads for extraction")
        
        # Function to extract a single file with improved error handling and path handling
        def extract_file(file_info):
            # Create target path - adjusted to handle root directory
            rel_path = Path(file_info['path'])
            
            # If path starts with the root directory name, strip it
            if rel_path.parts and rel_path.parts[0] == root_dir_name:
                if len(rel_path.parts) > 1:
                    target_path = output_dir / Path(*rel_path.parts[1:])
                else:
                    # Edge case: file directly in root directory
                    target_path = output_dir / rel_path.name
            else:
                # If path doesn't start with root dir, preserve as-is
                target_path = output_dir / rel_path
                
            # Ensure parent directory exists
            target_path.parent.mkdir(parents=True, exist_ok=True)
            
            try:
                # Use a temporary file for initial extraction to avoid corruption
                temp_path = f"{target_path}.tmp_{threading.get_ident()}"
                
                # Seek to file data (requires lock to prevent race conditions)
                with archive_lock:
                    archive_file.seek(file_info['offset'])
                    
                    # Read size of data block
                    try:
                        data_size = struct.unpack("<Q", archive_file.read(8))[0]
                        
                        # Sanity check on data size to prevent memory issues
                        if data_size < 0 or data_size > 10 * 1024 * 1024 * 1024:  # > 10GB is suspicious
                            return False, f"Invalid data size for {file_info['path']}: {data_size} bytes"
                        
                        # For compressed files, determine handling based on size
                        if metadata.get('compression', False):
                            if data_size > 100 * 1024 * 1024:  # > 100MB compressed
                                # For very large compressed files, use chunked reading with temp file
                                temp_comp_path = f"{target_path}.comp_{threading.get_ident()}"
                                try:
                                    # First, read compressed data to a temp file to reduce memory pressure
                                    with open(temp_comp_path, 'wb') as temp_comp:
                                        remaining = data_size
                                        while remaining > 0:
                                            chunk_size = min(remaining, self.BLOCK_SIZE)
                                            chunk = archive_file.read(chunk_size)
                                            if not chunk:
                                                raise EOFError(
                                                    f"Unexpected end of file while reading {file_info['path']}")
                                            temp_comp.write(chunk)
                                            remaining -= len(chunk)
                                    
                                    # Now decompress from the temp file
                                    import zlib
                                    with open(temp_comp_path, 'rb') as temp_comp, open(temp_path, 'wb') as temp_out:
                                        # Use streaming decompression
                                        decompressor = zlib.decompressobj()
                                        while True:
                                            chunk = temp_comp.read(self.BLOCK_SIZE)
                                            if not chunk:
                                                # Final chunk may contain padding
                                                final_data = decompressor.flush()
                                                if final_data:
                                                    temp_out.write(final_data)
                                                break
                                            decompressed_chunk = decompressor.decompress(chunk)
                                            temp_out.write(decompressed_chunk)
                                finally:
                                    # Clean up the compressed temp file
                                    try:
                                        if os.path.exists(temp_comp_path):
                                            os.unlink(temp_comp_path)
                                    except Exception:
                                        pass
                            else:
                                # For smaller compressed files, use in-memory approach
                                compressed_data = archive_file.read(data_size)
                                
                                # Decompress outside the lock
                                import zlib
                                try:
                                    decompressed = zlib.decompress(compressed_data)
                                    # Write directly to the temporary file
                                    with open(temp_path, 'wb') as temp_out:
                                        temp_out.write(decompressed)
                                except zlib.error as e:
                                    return False, f"Error decompressing {file_info['path']}: {e}"
                        else:
                            # For uncompressed files, read in chunks directly to the temp file
                            with open(temp_path, 'wb') as temp_out:
                                remaining = data_size
                                while remaining > 0:
                                    chunk_size = min(remaining, self.BLOCK_SIZE)
                                    chunk = archive_file.read(chunk_size)
                                    if not chunk:
                                        raise EOFError(f"Unexpected end of file while reading {file_info['path']}")
                                    temp_out.write(chunk)
                                    remaining -= len(chunk)
                    except struct.error:
                        return False, f"Invalid data structure for {file_info['path']}"
                    except EOFError as e:
                        return False, str(e)
                
                # Move the temporary file to the target path only if everything succeeded
                try:
                    # If target exists, remove it first (Windows needs this)
                    if os.path.exists(target_path):
                        os.unlink(target_path)
                    os.rename(temp_path, target_path)
                except Exception as e:
                    return False, f"Error moving temp file to final destination {file_info['path']}: {e}"
                
                # Restore file metadata if possible
                try:
                    os.utime(target_path, (file_info['mtime'], file_info['mtime']))
                    if hasattr(os, 'chmod'):
                        os.chmod(target_path, file_info['mode'])
                except Exception:
                    pass  # Ignore metadata restoration errors
                    
                return True, None
            except Exception as e:
                # Clean up temp file if it exists
                if temp_path and os.path.exists(temp_path):
                    try:
                        os.unlink(temp_path)
                    except Exception:
                        pass
                return False, f"Error extracting {file_info['path']}: {e}"
        
        # Process files in smaller batches for better memory management
        batch_size = 20  # Smaller batches to prevent memory issues
        successful_extractions = 0
        failed_extractions = 0
        errors = []
        
        # Show more detailed progress information
        print(f"Extracting {file_count} files in batches of {batch_size}")
        
        with Progress(
            TextColumn("[bold green]Extracting files...[/bold green]"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.1f}%"),
            TextColumn("({task.completed}/{task.total})"),
            TimeRemainingColumn()
        ) as progress:
            task = progress.add_task("Extracting...", total=file_count)
            
            for i in range(0, len(files), batch_size):
                batch = files[i:i+batch_size]
                
                # Extract this batch
                batch_results = thread_pool.parallel_map(
                    extract_file, 
                    batch, 
                    io_bound=True,
                    max_workers=max_workers
                )
                
                # Update statistics
                for success, error_msg in batch_results:
                    if success:
                        successful_extractions += 1
                    else:
                        failed_extractions += 1
                        if error_msg:
                            errors.append(error_msg)
                
                # Update progress
                progress.update(task, completed=i + len(batch))
                
                # Add a small delay between batches to reduce memory pressure
                if i + batch_size < len(files):
                    time.sleep(0.1)
        
        print(f"Extracted {successful_extractions}/{file_count} files successfully")
        if failed_extractions > 0:
            print(f"WARNING: {failed_extractions} files failed to extract")
            # Show at most 5 errors to avoid console spam
            for i, error in enumerate(errors[:5]):
                print(f"  Error {i+1}: {error}")
            if len(errors) > 5:
                print(f"  ...and {len(errors) - 5} more errors")
            
            if failed_extractions / file_count > 0.5:
                # Over 50% failure rate is critical
                raise ValueError("Critical failure: More than 50% of files failed to extract. "
                               "The archive may be corrupted or the password incorrect.")
        
        return metadata

    def is_valid_archive(self, file_path: Union[str, Path]) -> bool:
        """Check if a file appears to be a valid custom archive"""
        try:
            with open(file_path, 'rb') as f:
                # Check magic bytes
                header = f.read(len(self.HEADER_MAGIC))
                if header != self.HEADER_MAGIC:
                    return False
                
                # Try to read the metadata offset
                try:
                    metadata_offset = struct.unpack("<Q", f.read(8))[0]
                    
                    # Check if offset is reasonable
                    file_size = os.path.getsize(file_path)
                    if metadata_offset <= 0 or metadata_offset >= file_size:
                        return False
                    
                    # Try to read the metadata
                    f.seek(metadata_offset)
                    metadata_json = f.read()
                    metadata = json.loads(metadata_json.decode('utf-8'))
                    
                    # Verify basic metadata structure
                    required_keys = ['original_name', 'file_count', 'files']
                    for key in required_keys:
                        if key not in metadata:
                            return False
                    
                    return True
                except (struct.error, json.JSONDecodeError, OSError):
                    return False
        except Exception:
            return False
