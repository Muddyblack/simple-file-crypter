"""Threading utilities for improved performance"""
import concurrent.futures
import contextlib
import os
import platform
import queue
import threading
import time
from typing import Callable, List, Optional, TypeVar

import psutil  # You may need to install this: pip install psutil

T = TypeVar('T')
R = TypeVar('R')

class ThreadPoolManager:
    """
    Thread pool management for CPU-bound and IO-bound operations with optimized performance
    """
    
    @staticmethod
    def get_optimal_thread_count(io_bound: bool = False) -> int:
        """
        Get optimal thread count based on CPU cores and operation type
        
        Args:
            io_bound: Whether the operation is IO-bound (vs CPU-bound)
            
        Returns:
            Optimal thread count
        """
        try:
            cpu_count = psutil.cpu_count(logical=True)  # Gets logical cores for hyperthreading
            physical_cores = psutil.cpu_count(logical=False)  # Gets physical cores
        except Exception:
            # Fallback if psutil fails
            cpu_count = os.cpu_count() or 4
            physical_cores = max(1, cpu_count // 2)  # Rough estimate
            
        # Check available memory to prevent excessive threading
        try:
            mem = psutil.virtual_memory()
            mem_gb = mem.total / (1024**3)  # RAM in GB
            
            # Ensure we don't create too many threads on low-memory systems
            memory_factor = min(4, max(1, int(mem_gb / 2)))
        except Exception:
            memory_factor = 2  # Default factor
            
        if io_bound:
            # IO-bound tasks benefit from more threads than CPU cores
            # But we need to be more conservative with the limits
            io_limit = min(32, cpu_count * memory_factor)  # Reduced from 64
            
            # Check if the system is under memory pressure
            try:
                if mem.percent > 80:  # High memory usage already
                    io_limit = min(io_limit, cpu_count + 2)  # More conservative
            except Exception:
                pass
                
            return io_limit
        else:
            # CPU-bound tasks work best with thread count = physical cores
            # or slightly less if memory pressure is high
            try:
                if mem.percent > 80:  # High memory usage
                    return max(1, physical_cores - 1)
            except Exception:
                pass
                
            return physical_cores
    
    @staticmethod
    def _set_thread_affinity(thread_id: int = None, cpu_ids: List[int] = None):
        """
        Set CPU affinity for current thread if platform supports it
        """
        if platform.system() != "Windows" and platform.system() != "Linux":
            return  # Not supported on this platform
            
        try:
            # Get current process
            process = psutil.Process()
            if thread_id is None:
                # Current thread
                if cpu_ids is None:
                    return  # Nothing to do
                if platform.system() == "Linux":
                    # Linux-specific thread affinity
                    os.sched_setaffinity(0, cpu_ids)
                else:
                    # Windows - whole process affinity, less granular
                    process.cpu_affinity(cpu_ids)
        except Exception:
            pass  # Silently fail if affinity setting is not supported
    
    @staticmethod
    def parallel_map(func: Callable[[T], R], items: List[T], io_bound: bool = False, 
                   max_workers: Optional[int] = None, chunk_size: Optional[int] = None,
                   show_progress: bool = False) -> List[R]:
        """
        Execute a function on items in parallel and return results in order
        
        Args:
            func: The function to execute on each item
            items: List of items to process
            io_bound: Whether the operation is IO-bound
            max_workers: Maximum number of threads (default: auto-detect optimal)
            chunk_size: Optional chunk size for processing very large input lists
            show_progress: Whether to show a progress indicator
            
        Returns:
            List of results in the same order as input items
        """
        if not items:
            return []
            
        # Early optimization for small workloads to avoid thread overhead
        if len(items) == 1:
            return [func(items[0])]
            
        if len(items) <= 3 and not io_bound:
            return [func(item) for item in items]
            
        if max_workers is None:
            max_workers = ThreadPoolManager.get_optimal_thread_count(io_bound)
            
        # Use at most as many workers as items
        max_workers = min(max_workers, len(items))
        
        # For very large lists, use chunked processing
        if chunk_size and len(items) > chunk_size * max_workers * 2:
            return ThreadPoolManager.chunked_parallel_map(func, items, chunk_size, io_bound, max_workers, show_progress)
            
        # Create a thread pool with a custom initializer for CPU-bound tasks
        if not io_bound:
            # Custom thread pool that sets CPU affinity 
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers, 
                                                      thread_name_prefix="cpu_worker") as executor:
                # Submit all work and maintain order with future objects
                futures = [executor.submit(func, item) for item in items]
                
                if show_progress:
                    total = len(futures)
                    completed = 0
                    print(f"Processing {total} items...")
                    
                    # Monitor and show progress
                    results = []
                    for future in concurrent.futures.as_completed(futures):
                        completed += 1
                        if completed % max(1, total // 100) == 0:  # Update every 1%
                            print(f"\rProgress: {completed}/{total} ({completed/total*100:.1f}%)", end="", flush=True)
                        results.append(future.result())
                    print("\rProgress: Completed 100%          ")
                    return results
                else:
                    # Return results in order as they complete
                    return [future.result() for future in concurrent.futures.as_completed(futures)]
        else:
            # Standard thread pool for IO-bound tasks
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers, 
                                                      thread_name_prefix="io_worker") as executor:
                # Use map for IO-bound as it's more efficient for this case
                return list(executor.map(func, items))
    
    @staticmethod
    def chunked_parallel_map(func: Callable[[T], R], items: List[T], chunk_size: int,
                           io_bound: bool = False, max_workers: Optional[int] = None,
                           show_progress: bool = False) -> List[R]:
        """
        Execute a function on items in parallel, processing in chunks to control memory usage
        
        Args:
            func: Function to call on each item
            items: List of items to process
            chunk_size: Number of items to process in each chunk
            io_bound: Whether the operation is IO-bound
            max_workers: Maximum number of threads
            show_progress: Whether to show a progress indicator
            
        Returns:
            List of results
        """
        if not items:
            return []
            
        if max_workers is None:
            max_workers = ThreadPoolManager.get_optimal_thread_count(io_bound)
        
        # For very large item lists, be even more conservative with threads
        if len(items) > 10000:
            max_workers = min(max_workers, 4)
        
        results = []
        total_chunks = (len(items) + chunk_size - 1) // chunk_size
        
        if show_progress:
            print(f"Processing {len(items)} items in {total_chunks} chunks...")
        
        # Process items in chunks to control memory usage
        for i in range(0, len(items), chunk_size):
            if show_progress:
                current_chunk = i // chunk_size + 1
                print(f"\rProcessing chunk {current_chunk}/{total_chunks} ({current_chunk/total_chunks*100:.1f}%)", 
                      end="", flush=True)
                
            chunk = items[i:i + chunk_size]
            chunk_results = ThreadPoolManager.parallel_map(func, chunk, io_bound, max_workers)
            results.extend(chunk_results)
            
            # Add a small delay between chunks to allow garbage collection
            if len(items) > 1000 and i + chunk_size < len(items):
                time.sleep(0.05)
        
        if show_progress:
            print("\rAll chunks processed successfully!            ")
            
        return results
    
    @staticmethod
    def parallel_process_queue(queue_items: queue.Queue, process_func: Callable, 
                             num_workers: Optional[int] = None, io_bound: bool = True,
                             batch_size: int = 1) -> None:
        """
        Process items from a queue in parallel until the queue is empty
        
        Args:
            queue_items: Queue containing items to process
            process_func: Function to call on each item (or batch of items if batch_size > 1)
            num_workers: Number of worker threads (default: auto-detect optimal)
            io_bound: Whether the operation is IO-bound
            batch_size: Number of items to process in each batch (for better efficiency)
        """
        if num_workers is None:
            num_workers = ThreadPoolManager.get_optimal_thread_count(io_bound)
        
        # Worker function depends on batch size
        if batch_size <= 1:
            def worker():
                while True:
                    try:
                        item = queue_items.get(block=False)
                        try:
                            process_func(item)
                        except Exception as e:
                            print(f"Error processing queue item: {e}")
                        finally:
                            queue_items.task_done()
                    except queue.Empty:
                        # Add a small sleep to reduce CPU usage when queue is temporarily empty
                        time.sleep(0.001)
                        # Check if the queue is truly empty (all workers done and queue empty)
                        if queue_items.empty():
                            break
        else:
            # Batch processing for better efficiency
            def worker():
                while True:
                    batch = []
                    # Try to fill a batch
                    for _ in range(batch_size):
                        try:
                            item = queue_items.get(block=False)
                            batch.append(item)
                        except queue.Empty:
                            break
                    
                    # If we got items, process them
                    if batch:
                        try:
                            process_func(batch)
                        except Exception as e:
                            print(f"Error processing batch: {e}")
                        finally:
                            # Mark all items as done
                            for _ in range(len(batch)):
                                queue_items.task_done()
                    else:
                        # Empty batch means the queue might be empty
                        time.sleep(0.001)
                        if queue_items.empty():
                            break
        
        # Create and start worker threads
        threads = []
        for i in range(num_workers):
            thread = threading.Thread(target=worker, name=f"queue_worker_{i}")
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Wait for all queue items to be processed
        queue_items.join()
        
        # Wait for all threads to finish
        for thread in threads:
            thread.join(timeout=0.5)  # Short timeout since the queue is already empty
    
    @staticmethod
    def parallel_for_each(items: List[T], action: Callable[[T], None], io_bound: bool = False,
                        max_workers: Optional[int] = None, chunk_size: Optional[int] = None) -> None:
        """
        Execute an action on each item in parallel, ignoring results
        
        Args:
            items: List of items to process
            action: Function to call on each item
            io_bound: Whether the operation is IO-bound
            max_workers: Maximum number of threads
            chunk_size: Optional chunk size for very large lists
        """
        if not items:
            return
            
        if max_workers is None:
            max_workers = ThreadPoolManager.get_optimal_thread_count(io_bound)
        
        # For very large lists, use chunked processing
        if chunk_size and len(items) > chunk_size * max_workers * 2:
            chunks = [items[i:i + chunk_size] for i in range(0, len(items), chunk_size)]
            
            def process_chunk(chunk):
                for item in chunk:
                    action(item)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit chunks as individual tasks
                futures = [executor.submit(process_chunk, chunk) for chunk in chunks]
                # Wait for all chunks to complete
                concurrent.futures.wait(futures)
                # Check for exceptions
                for future in futures:
                    # This will raise any exception that occurred during execution
                    future.result()
        else:
            # Process normally for smaller lists
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Process all items and ignore results
                list(executor.map(action, items))

    @staticmethod
    @contextlib.contextmanager
    def timed_execution(operation_name: str = "Operation"):
        """
        Context manager to time operations
        
        Usage:
            with ThreadPoolManager.timed_execution("My Task"):
                # do something
        """
        start_time = time.time()
        try:
            yield
        finally:
            elapsed = time.time() - start_time
            print(f"{operation_name} completed in {elapsed:.2f} seconds")

    @staticmethod
    def work_stealing_map(func: Callable[[T], R], items: List[T], 
                        chunk_size: int = 5, 
                        max_workers: Optional[int] = None,
                        io_bound: bool = False) -> List[R]:
        """
        Execute parallel map with work-stealing for better load balancing
        
        Args:
            func: Function to apply to each item
            items: List of input items
            chunk_size: Initial chunk size for work distribution
            max_workers: Number of worker threads
            io_bound: Whether the operation is IO-bound
            
        Returns:
            List of results
        """
        if not items:
            return []
            
        if max_workers is None:
            max_workers = ThreadPoolManager.get_optimal_thread_count(io_bound)
        
        # Prepare shared resources
        task_queue = queue.Queue()
        result_dict = {}
        lock = threading.RLock()
        
        # Add all work items to the queue in chunks
        for i in range(0, len(items), chunk_size):
            chunk = items[i:i+chunk_size]
            chunk_indices = list(range(i, min(i+chunk_size, len(items))))
            task_queue.put((chunk, chunk_indices))
        
        def worker():
            while True:
                try:
                    work_chunk, indices = task_queue.get(block=False)
                    try:
                        # Process chunk
                        for item, idx in zip(work_chunk, indices, strict=False):
                            result = func(item)
                            with lock:
                                result_dict[idx] = result
                    finally:
                        task_queue.task_done()
                except queue.Empty:
                    break
        
        # Start worker threads
        threads = []
        for _ in range(max_workers):
            thread = threading.Thread(target=worker)
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Wait for all work to be done
        task_queue.join()
        
        # Collect results in original order
        return [result_dict[i] for i in range(len(items))]

# Global instance for easy access
thread_pool = ThreadPoolManager()