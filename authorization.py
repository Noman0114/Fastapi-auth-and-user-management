from fastapi import HTTPException, status
from typing import Dict, Any, Optional, List

# Define roles and their hierarchy
ROLES = {
    "user": ["user"],
    "moderator": ["user", "moderator"],
    "admin": ["user", "moderator", "admin"]
}

# Define permissions
PERMISSIONS = {
    "read_own_profile": ["user", "moderator", "admin"],
    "update_own_profile": ["user", "moderator", "admin"],
    "delete_own_profile": ["user", "moderator", "admin"],
    "read_any_profile": ["moderator", "admin"],
    "update_any_profile": ["admin"],
    "delete_any_profile": ["admin"],
    "manage_roles": ["admin"],
    "read_permissions": ["admin"],
    "update_permissions": ["admin"]
}

# Authorization helper functions
def authorize(user_id: int, user_role: str, action: str, resource_id: Optional[int] = None, owner_id: Optional[int] = None):
    """
    Check if a user is authorized to perform an action
    
    Args:
        user_id: The ID of the user trying to perform the action
        user_role: The role of the user
        action: The action being performed
        resource_id: The ID of the resource (optional)
        owner_id: The ID of the resource owner (optional)
    
    Returns:
        True if authorized, raises HTTPException if not
    """
    # Check if action requires resource ownership
    own_resource_actions = [
        "read_own_profile", 
        "update_own_profile", 
        "delete_own_profile"
    ]
    
    # Simple case: admin can do anything
    if user_role == "admin":
        return True
    
    # Check if the user has permission for this action
    if action not in PERMISSIONS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Unknown permission: {action}"
        )
    
    allowed_roles = PERMISSIONS[action]
    if user_role not in allowed_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to perform this action"
        )
    
    # For actions on resources, check ownership if required
    if action in own_resource_actions and owner_id is not None and user_id != owner_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to perform this action on another user's resource"
        )
    
    return True

def get_user_permissions(role: str) -> List[str]:
    """
    Get all permissions available to a role
    
    Args:
        role: The role to get permissions for
    
    Returns:
        List of permission names
    """
    return [perm for perm, roles in PERMISSIONS.items() if role in roles]

# Role management functions
def is_valid_role(role: str) -> bool:
    """Check if a role is valid"""
    return role in ROLES

def get_all_roles() -> Dict[str, List[str]]:
    """Get all roles and their hierarchies"""
    return ROLES

def get_all_permissions() -> Dict[str, List[str]]:
    """Get all permissions and the roles that have them"""
    return PERMISSIONS 