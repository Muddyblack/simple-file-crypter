"""
Progress indicators and animations for FileCrypter.
These components provide visual feedback during longer operations.
"""

from time import sleep

from rich.live import Live
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeRemainingColumn
from rich.table import Table


def create_progress_indicator():
    """Create and return a configurable progress bar."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TextColumn("[bold]{task.percentage:>3.0f}%"),
        TimeRemainingColumn()
    )

def with_progress(func, description="Processing", *args, **kwargs):
    """
    Execute a function with a progress bar.
    
    Args:
        func: Function to execute
        description: Description for the progress bar
        *args, **kwargs: Arguments to pass to the function
    
    Returns:
        The result of the function
    """
    with create_progress_indicator() as progress:
        task = progress.add_task(f"[blue]{description}...", total=100)
        
        # Create a wrapper to update progress
        def progress_callback(percent):
            progress.update(task, completed=percent)
        
        # Add progress_callback to kwargs
        kwargs['progress_callback'] = progress_callback
        
        # Call the function
        result = func(*args, **kwargs)
        
        # Ensure progress is complete
        progress.update(task, completed=100)
        
        return result

def show_processing_animation(message="Processing", duration=2.5):
    """
    Show an animated processing indicator.
    
    Args:
        message: Message to display
        duration: Duration in seconds
    """
    with Live(refresh_per_second=4) as live:
        dots_max = 3
        steps = int(duration * 4)  # 4 updates per second
        
        for i in range(steps):
            dots = '.' * (1 + (i % dots_max))
            spaces = ' ' * (dots_max - (i % dots_max))
            
            table = Table(box=None, show_header=False, padding=(0, 1))
            table.add_column()
            table.add_row(f"[bold blue]{message}{dots}{spaces}[/bold blue]")
            
            live.update(table)
            sleep(1/4)  # 0.25 seconds
