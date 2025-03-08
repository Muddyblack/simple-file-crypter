import os
import time

from rich.panel import Panel

from . import console


def display_selected_file(file_path):
    """Display selected file with nice formatting and details"""
    if not file_path:
        return
        
    try:
        file_size = os.path.getsize(file_path)
        mod_time = os.path.getmtime(file_path)
        create_time = os.path.getctime(file_path)  # Get creation time
        
        # Format size nicely
        if file_size < 1024:
            size_str = f"{file_size} bytes"
        elif file_size < 1024 * 1024:
            size_str = f"{file_size/1024:.1f} KB"
        else:
            size_str = f"{file_size/(1024*1024):.1f} MB"
            
        # Format time nicely
        mod_time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mod_time))
        create_time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(create_time))  # Format creation time
        
        # Create a nice panel with file details
        file_info = f"[bold]{os.path.basename(file_path)}[/bold]\n"
        file_info += f"[dim]Path:[/dim] {os.path.dirname(file_path)}\n"
        file_info += f"[dim]Size:[/dim] {size_str}\n"
        file_info += f"[dim]Modified:[/dim] {mod_time_str}\n"
        file_info += f"[dim]Created:[/dim] {create_time_str}"  # Add creation time
        
        # Display with appropriate icon based on file type
        extension = os.path.splitext(file_path)[1].lower()
        
        if extension in ['.sfc', '.bin']:
            icon = "🔒"  # Lock for encrypted files
        elif extension in ['.pem', '.key']:
            icon = "🔑"  # Key for key files
        elif extension in ['.txt', '.md', '.log']:
            icon = "📄"  # Document for text files
        elif extension in ['.jpg', '.png', '.gif', '.bmp']:
            icon = "🖼️"  # Picture for image files
        elif extension in ['.mp3', '.wav', '.flac']:
            icon = "🎵"  # Music note for audio
        elif extension in ['.mp4', '.avi', '.mov']:
            icon = "🎬"  # Clapper for video
        elif extension in ['.zip', '.rar', '.tar', '.gz']:
            icon = "📦"  # Package for archives
        else:
            icon = "📁"  # Generic file icon
            
        console.print()
        console.print(Panel(file_info, 
                           title=f"[bold green]{icon} Selected File[/bold green]",
                           border_style="blue",
                           padding=(1, 2)))
    except Exception as e:
        # Fallback to simple display if there's an error getting file details
        console.print(f"\n[bold blue]Selected file:[/bold blue] {file_path}")
        console.print(f"[dim]Error getting details: {str(e)}[/dim]")

def display_selected_directory(dir_path):
    """Display selected directory with nice formatting and details"""
    if not dir_path:
        return
        
    try:
        # Count files and subdirectories
        file_count = 0
        dir_count = 0
        total_size = 0
        total_items = 0  # Total number of items
        
        # Get immediate children only (don't recurse for performance)
        for item in os.listdir(dir_path)[:20]:  # Limit to 20 items for performance
            item_path = os.path.join(dir_path, item)
            if os.path.isfile(item_path):
                file_count += 1
                total_size += os.path.getsize(item_path)
            elif os.path.isdir(item_path):
                dir_count += 1
            total_items += 1  # Increment total items count
                
        # Format size nicely
        if total_size < 1024:
            size_str = f"{total_size} bytes"
        elif total_size < 1024 * 1024:
            size_str = f"{total_size/1024:.1f} KB"
        else:
            size_str = f"{total_size/(1024*1024):.1f} MB"
            
        # Create a nice panel with directory details
        dir_info = f"[bold]{os.path.basename(dir_path)}[/bold]\n"
        dir_info += f"[dim]Path:[/dim] {os.path.dirname(dir_path)}\n"
        
        # Add directory contents summary
        if file_count > 0 or dir_count > 0:
            content_summary = []
            if file_count > 0:
                content_summary.append(f"{file_count} file{'s' if file_count != 1 else ''}")
            if dir_count > 0:
                content_summary.append(f"{dir_count} folder{'s' if dir_count != 1 else ''}")
                
            dir_info += f"[dim]Contains:[/dim] {', '.join(content_summary)}\n"
            dir_info += f"[dim]Size (top level):[/dim] {size_str}\n"
            dir_info += f"[dim]Total items:[/dim] {total_items}"  # Add total items count
        else:
            dir_info += "[dim]Empty directory[/dim]"
            
        console.print()
        console.print(Panel(dir_info, 
                           title="[bold green]📂 Selected Directory[/bold green]",
                           border_style="blue",
                           padding=(1, 2)))
    except Exception as e:
        # Fallback to simple display if there's an error
        console.print(f"\n[bold blue]Selected directory:[/bold blue] {dir_path}")
        console.print(f"[dim]Error getting details: {str(e)}[/dim]")
