import concurrent.futures
import threading
import time
from typing import Any, Callable, List, Optional, Tuple, TypeVar

from rich.progress import Progress, TaskID

T = TypeVar('T')
R = TypeVar('R')

class ParallelProgressTracker:
    """Helper class to track progress across multiple threads"""
    
    def __init__(self, progress: Progress, task_id: TaskID, total: int):
        self.progress = progress
        self.task_id = task_id
        self.total = total
        self.lock = threading.Lock()
        self.completed = 0
    
    def update(self, increment: int = 1):
        """Update progress by the specified increment"""
        with self.lock:
            self.completed += increment
            self.progress.update(self.task_id, completed=min(self.completed, self.total))

def execute_with_progress(
    operation_func: Callable[..., Any],
    operation_args: tuple,
    task_description: str = "Processing...",
    simulate_steps: bool = True,
    pre_op_progress: int = 90,
    post_op_progress: Optional[int] = None
):
    """
    Execute an operation with a progress bar
    
    Args:
        operation_func: The function to execute
        operation_args: Arguments to pass to the function
        task_description: Description shown in the progress bar
        success_message: Message shown on success
        error_message: Message shown on error
        simulate_steps: Whether to simulate progress steps before/after actual operation
        pre_op_progress: Progress percentage before executing the actual operation
        post_op_progress: Progress percentage after operation (defaults to 100)
    
    Returns:
        The result of the operation_func
    
    Raises:
        Exception: Any exception raised by operation_func
    """
    if post_op_progress is None:
        post_op_progress = 100
    
    result = None
    with Progress() as progress:
        task = progress.add_task(f"[green]{task_description}", total=100)
        
        try:
            # Simulate initial progress if requested
            if simulate_steps and pre_op_progress > 0:
                step = min(10, pre_op_progress // 5)
                for i in range(0, pre_op_progress, step):
                    progress.update(task, completed=i)
                    time.sleep(0.1)
            
            # Execute the actual operation
            result = operation_func(*operation_args)
            
            # Simulate remaining progress if requested
            if simulate_steps and post_op_progress > pre_op_progress:
                remaining = post_op_progress - pre_op_progress
                step = min(10, remaining // 3) or 1
                for i in range(pre_op_progress, post_op_progress, step):
                    progress.update(task, completed=i)
                    time.sleep(0.05)
            
            # Ensure we reach the final progress percentage
            progress.update(task, completed=post_op_progress)
            
            return result
            
        except Exception as e:
            # Let the caller handle the error display
            raise e

def execute_parallel_with_progress(
    task_items: List[T],
    process_func: Callable[[T], R],
    task_description: str = "Processing...",
    max_workers: Optional[int] = None,
    io_bound: bool = True
) -> List[R]:
    """
    Execute tasks in parallel with a progress bar
    
    Args:
        task_items: List of items to process
        process_func: Function to call for each item
        task_description: Description for the progress bar
        max_workers: Max number of worker threads (None = auto)
        io_bound: Whether tasks are IO bound (vs CPU bound)
    
    Returns:
        List of results in the same order as input items
    """
    if not task_items:
        return []
        
    # Get number of workers based on system capabilities
    if max_workers is None:
        import os
        cpu_count = os.cpu_count() or 4
        max_workers = cpu_count * 2 if io_bound else cpu_count
        
    # Use at most as many workers as tasks
    max_workers = min(max_workers, len(task_items))
    
    results = [None] * len(task_items)
    
    with Progress() as progress:
        task_id = progress.add_task(f"[green]{task_description}", total=len(task_items))
        
        # Create a thread-safe progress tracker
        tracker = ParallelProgressTracker(progress, task_id, len(task_items))
        
        # Function that updates progress after processing each item
        def process_and_update(idx_item: Tuple[int, T]) -> Tuple[int, R]:
            idx, item = idx_item
            try:
                result = process_func(item)
                tracker.update()
                return idx, result
            except Exception as e:
                tracker.update()
                return idx, e  # Return exception as result
        
        # Execute tasks with progress tracking
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks with their indices
            futures = [
                executor.submit(process_and_update, (i, item))
                for i, item in enumerate(task_items)
            ]
            
            # Collect results as they complete, preserving original order via index
            for future in concurrent.futures.as_completed(futures):
                idx, result = future.result()
                results[idx] = result
                
            # Check if any results are exceptions
            exceptions = [r for r in results if isinstance(r, Exception)]
            if exceptions:
                raise exceptions[0]  # Re-raise the first exception
                
            return results

def execute_chunked_with_progress(
    operation_func: Callable[[List[T]], List[R]],
    items: List[T],
    chunk_size: int = 100,
    task_description: str = "Processing in chunks...",
    show_chunk_progress: bool = False
) -> List[R]:
    """
    Process items in chunks with a progress bar
    
    Args:
        operation_func: Function that processes a chunk of items
        items: List of all items to process
        chunk_size: Number of items per chunk
        task_description: Description for the progress bar
        show_chunk_progress: Whether to show progress for each chunk
        
    Returns:
        List of results for all processed items
    """
    if not items:
        return []
    
    total_items = len(items)
    total_chunks = (total_items + chunk_size - 1) // chunk_size  # Ceiling division
    results = []
    
    with Progress() as progress:
        main_task = progress.add_task(f"[green]{task_description}", total=total_items)
        chunk_task = None
        
        for i in range(0, total_items, chunk_size):
            # Get current chunk
            chunk = items[i:i+chunk_size]
            chunk_len = len(chunk)
            
            # Create or update chunk progress task
            if show_chunk_progress:
                if chunk_task is not None:
                    progress.remove_task(chunk_task)
                chunk_task = progress.add_task(
                    f"[cyan]Chunk {i//chunk_size + 1}/{total_chunks}...", 
                    total=chunk_len
                )
            
            # Process the chunk
            chunk_results = operation_func(chunk)
            results.extend(chunk_results)
            
            # Update overall progress
            progress.update(main_task, completed=i + chunk_len)
    
    return results

class MultiTaskProgress:
    """Helper class to manage multiple progress tasks at once"""
    
    def __init__(self, total_description: str = "Overall Progress"):
        """Initialize with a main task description"""
        self.progress = Progress()
        self.total_task = self.progress.add_task(f"[bold green]{total_description}", total=100)
        self.sub_tasks = {}
        self.started = False
        self.completed_weight = 0
        self.total_weight = 0
    
    def add_task(self, description: str, weight: int = 1) -> str:
        """
        Add a subtask with a weighted importance
        
        Args:
            description: Task description
            weight: Relative importance weight for overall progress
            
        Returns:
            Task ID string
        """
        task_id = f"task_{len(self.sub_tasks)}"
        self.sub_tasks[task_id] = {
            'description': description,
            'progress_id': None,  # Will be set when started
            'weight': weight,
            'completed': 0
        }
        self.total_weight += weight
        return task_id
    
    def start(self):
        """Start the progress display"""
        if not self.started:
            self.progress.start()
            # Create actual Rich progress tasks for each subtask
            for _task_id, task_info in self.sub_tasks.items():
                progress_id = self.progress.add_task(
                    f"[blue]{task_info['description']}", 
                    total=100
                )
                task_info['progress_id'] = progress_id
            self.started = True
    
    def update_task(self, task_id: str, completed: float):
        """
        Update a specific task's progress (0-100)
        
        Args:
            task_id: Task identifier returned from add_task
            completed: Progress percentage (0-100)
        """
        if not self.started:
            self.start()
            
        task_info = self.sub_tasks.get(task_id)
        if task_info:
            # Calculate the delta in overall weighted progress
            old_completed = task_info['completed']
            new_completed = min(100, max(0, completed))  # Clamp to 0-100
            
            # Update the total completed weight
            task_weight = task_info['weight']
            weight_delta = (new_completed - old_completed) * task_weight / 100
            self.completed_weight += weight_delta
            
            # Update the individual task
            task_info['completed'] = new_completed
            self.progress.update(task_info['progress_id'], completed=new_completed)
            
            # Update the overall progress
            if self.total_weight > 0:
                overall_percent = (self.completed_weight / self.total_weight) * 100
                self.progress.update(self.total_task, completed=overall_percent)
    
    def complete_task(self, task_id: str):
        """Mark a task as complete"""
        self.update_task(task_id, 100)
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.progress.stop()
