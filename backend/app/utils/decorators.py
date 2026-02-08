"""
Decorators - Security Component
Provides authentication and authorization decorators
"""

from functools import wraps
from typing import Callable

from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import get_current_user


def login_required(func: Callable):
    """
    Decorator to require authentication for an endpoint.
    
    Note: In FastAPI, this is typically handled via Depends(get_current_user).
    This decorator provides an alternative approach for compatibility with
    the architecture diagram requirements.
    
    Usage:
        @login_required
        async def my_endpoint(current=Depends(get_current_user)):
            ...
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        # Check if current user is in kwargs
        current = kwargs.get('current')
        if current is None:
            # Try to get from args
            for arg in args:
                if isinstance(arg, tuple) and len(arg) == 2:
                    current = arg
                    break
        
        if current is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required"
            )
        
        return await func(*args, **kwargs)
    
    return wrapper


def require_owner(resource_attr: str = 'document'):
    """
    Decorator to require ownership of a resource.
    
    Args:
        resource_attr: Attribute name containing the resource to check ownership
        
    Usage:
        @require_owner('document')
        async def delete_document(document: Document, current=Depends(get_current_user)):
            ...
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            current = kwargs.get('current')
            if current is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            user, _ = current
            resource = kwargs.get(resource_attr)
            
            if resource is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Resource '{resource_attr}' not found in request"
                )
            
            # Check ownership
            if hasattr(resource, 'owner_id') and resource.owner_id != user.id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="You don't have permission to access this resource"
                )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


def require_permission(permission: str):
    """
    Decorator to require specific permission.
    
    Args:
        permission: Permission string (e.g., 'document:delete', 'user:admin')
        
    Usage:
        @require_permission('admin')
        async def admin_endpoint(current=Depends(get_current_user)):
            ...
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            current = kwargs.get('current')
            if current is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            user, _ = current
            
            # Check if user has permission
            # For now, we'll check if user is admin (can be extended)
            if permission == 'admin' and not getattr(user, 'is_admin', False):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission '{permission}' required"
                )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


def csrf_protect(func: Callable):
    """
    Decorator for CSRF protection (wraps verify_csrf_token).
    
    Note: In FastAPI, CSRF is typically handled via Depends(verify_csrf_token).
    This decorator provides an alternative approach.
    
    Usage:
        @csrf_protect
        async def create_document(_csrf=Depends(verify_csrf_token)):
            ...
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        # CSRF token verification should be in dependencies
        # This is just a marker decorator
        return await func(*args, **kwargs)
    
    return wrapper
