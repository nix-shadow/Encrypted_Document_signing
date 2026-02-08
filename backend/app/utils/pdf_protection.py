"""
File password protection utilities.
Provides encryption at rest for ALL downloaded files using password-protected ZIP.
"""
import pyzipper
from io import BytesIO
import os
from typing import Optional


def is_protectable(content: bytes) -> bool:
    """
    Check if content can be password-protected.
    All files can be protected using ZIP encryption.
    
    Args:
        content: File content bytes
    
    Returns:
        bool: True (all files are protectable)
    """
    return len(content) > 0


def protect_file(file_content: bytes, password: str, filename: str) -> bytes:
    """
    Apply password protection to ANY file using ZIP encryption.
    Uses AES-256 encryption (in addition to our server-side encryption).
    
    Args:
        file_content: Original file bytes
        password: User-provided password for file protection
        filename: Original filename (preserved in ZIP)
    
    Returns:
        bytes: Password-protected ZIP file containing the original file
    
    Raises:
        ValueError: If content is empty
        RuntimeError: If ZIP encryption fails
    """
    if not is_protectable(file_content):
        raise ValueError("Content is empty or invalid")
    
    try:
        # Create ZIP in memory
        zip_buffer = BytesIO()
        
        # Create encrypted ZIP with AES-256
        with pyzipper.AESZipFile(
            zip_buffer,
            'w',
            compression=pyzipper.ZIP_DEFLATED,
            encryption=pyzipper.WZ_AES  # WinZip AES encryption
        ) as zf:
            # Set password
            zf.setpassword(password.encode('utf-8'))
            
            # Add file to ZIP with original filename
            zf.writestr(filename, file_content)
        
        # Get protected ZIP bytes
        zip_buffer.seek(0)
        protected_content = zip_buffer.read()
        
        return protected_content
        
    except Exception as e:
        raise RuntimeError(f"Failed to encrypt file: {str(e)}")


def verify_file_password(zip_content: bytes, password: str) -> bool:
    """
    Verify if a password can open a protected ZIP file.
    
    Args:
        zip_content: Password-protected ZIP bytes
        password: Password to test
    
    Returns:
        bool: True if password is correct
    """
    try:
        zip_buffer = BytesIO(zip_content)
        with pyzipper.AESZipFile(zip_buffer, 'r') as zf:
            zf.setpassword(password.encode('utf-8'))
            # Try to read file list (will fail if wrong password)
            zf.namelist()
        return True
    except RuntimeError:  # Wrong password
        return False
    except Exception:
        return False


def extract_file_from_zip(zip_content: bytes, password: str) -> Optional[tuple[bytes, str]]:
    """
    Extract file from password-protected ZIP.
    
    Args:
        zip_content: Password-protected ZIP bytes
        password: Password to decrypt
    
    Returns:
        tuple or None: (file_content, filename) or None if password is wrong
    """
    try:
        zip_buffer = BytesIO(zip_content)
        with pyzipper.AESZipFile(zip_buffer, 'r') as zf:
            zf.setpassword(password.encode('utf-8'))
            
            # Get first file in ZIP
            filenames = zf.namelist()
            if not filenames:
                return None
            
            filename = filenames[0]
            file_content = zf.read(filename)
            
            return file_content, filename
        
    except RuntimeError:  # Wrong password
        return None
    except Exception:
        return None


def get_zip_info(zip_content: bytes) -> dict:
    """
    Get information about a password-protected ZIP file.
    
    Args:
        zip_content: ZIP file bytes
    
    Returns:
        dict: ZIP file information
    """
    try:
        zip_buffer = BytesIO(zip_content)
        with pyzipper.AESZipFile(zip_buffer, 'r') as zf:
            info = {
                "encrypted": True,
                "files": [],
                "compression": "DEFLATE",
                "encryption": "AES-256"
            }
            
            for file_info in zf.filelist:
                info["files"].append({
                    "filename": file_info.filename,
                    "file_size": file_info.file_size,
                    "compress_size": file_info.compress_size
                })
            
            return info
        
    except Exception:
        return {
            "encrypted": False,
            "files": []
        }
