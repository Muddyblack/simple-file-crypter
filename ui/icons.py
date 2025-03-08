"""
Icon and status indicator utilities for FileCrypter.
These functions provide consistent visual indicators throughout the application.
"""

def get_key_status_icon(key_type):
    """
    Get an icon representing the key status.
    
    Args:
        key_type: Type of key (private, public, trusted, revoked)
    
    Returns:
        Unicode icon character
    """
    icons = {
        "private": "🔒",  # Lock for private
        "public": "🔓",   # Unlocked for public
        "trusted": "✅",  # Checkmark for trusted
        "revoked": "❌",   # X for revoked
        "expired": "⏰",   # Clock for expired
        "unknown": "❓"    # Question mark for unknown
    }
    return icons.get(key_type.lower(), "❓")

def get_operation_status_icon(status):
    """
    Get an icon representing operation status.
    
    Args:
        status: Operation status (success, error, warning, info)
    
    Returns:
        Unicode icon character
    """
    icons = {
        "success": "✅",   # Checkmark for success
        "error": "❌",     # X for error
        "warning": "⚠️",   # Warning for warning
        "info": "ℹ️",      # Info symbol for info
        "pending": "⏳",   # Hourglass for pending
        "locked": "🔒",    # Lock for locked
        "unlocked": "🔓",  # Unlocked for unlocked
        "encrypted": "🔐", # Lock with key for encrypted
        "decrypted": "📄"  # Document for decrypted
    }
    return icons.get(status.lower(), "")
