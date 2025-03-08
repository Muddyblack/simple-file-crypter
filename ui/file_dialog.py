import tkinter as tk
from tkinter import filedialog


def open_file_dialog(title="Select a file"):
    """Open a file selection dialog"""
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    root.attributes('-topmost', True)
    root.focus_force()
    file_path = filedialog.askopenfilename(title=title)
    root.destroy()
    return file_path

def open_save_dialog(title="Save file as"):
    """Open a save file dialog"""
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    root.attributes('-topmost', True)
    root.focus_force()
    file_path = filedialog.asksaveasfilename(title=title)
    root.destroy()
    return file_path

def open_directory_dialog(title="Select a directory"):
    """Open a directory selection dialog"""
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    root.attributes('-topmost', True)
    root.focus_force()
    dir_path = filedialog.askdirectory(title=title)
    root.destroy()
    return dir_path
