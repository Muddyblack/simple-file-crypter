
def clean_path(path: str) -> str:
    """
    Clean up file paths from drag and drop or copy-paste operations
    Handles Windows command prompt artifacts like '&' and quotes
    """
    # Handle Windows command prompt special characters and PowerShell/CMD artifacts
    path = path.strip()
    
    # Remove leading ampersand and any following spaces (Windows CMD/PS artifact)
    if path.startswith('&'):
        path = path.lstrip('& ')
    
    # Handle paths encased in quotes (single or double)
    if (path.startswith('"') and path.endswith('"')) or (path.startswith("'") and path.endswith("'")):
        path = path[1:-1]
    
    # Remove any other surrounding quotes or whitespace
    path = path.strip("'\"").strip()
    
    return path
