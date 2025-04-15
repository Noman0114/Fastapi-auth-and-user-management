import db
from typing import List, Dict, Any, Optional, Tuple

def get_all_roles():
    """
    Retrieve all roles from the database
    """
    conn = db.get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, name, description FROM roles")
    roles = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return [{"id": role[0], "name": role[1], "description": role[2]} for role in roles]

def get_role_by_name(role_name: str):
    """
    Retrieve a role by name
    """
    conn = db.get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, name, description FROM roles WHERE name = %s", (role_name,))
    role = cursor.fetchone()
    
    cursor.close()
    conn.close()
    
    if role:
        return {"id": role[0], "name": role[1], "description": role[2]}
    return None

def create_role(name: str, description: str):
    """
    Create a new role
    """
    conn = db.get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "INSERT INTO roles (name, description) VALUES (%s, %s) RETURNING id", 
            (name, description)
        )
        role_id = cursor.fetchone()[0]
        conn.commit()
        
        role = {"id": role_id, "name": name, "description": description}
    except Exception as e:
        conn.rollback()
        print(f"Error creating role: {e}")
        role = None
    finally:
        cursor.close()
        conn.close()
        
    return role

def update_role(role_id: int, data: Dict[str, Any]):
    """
    Update a role
    """
    conn = db.get_connection()
    cursor = conn.cursor()
    
    updates = []
    values = []
    
    if "name" in data:
        updates.append("name = %s")
        values.append(data["name"])
    
    if "description" in data:
        updates.append("description = %s")
        values.append(data["description"])
    
    if not updates:
        cursor.close()
        conn.close()
        return None
    
    values.append(role_id)
    
    try:
        cursor.execute(
            f"UPDATE roles SET {', '.join(updates)} WHERE id = %s RETURNING id, name, description",
            values
        )
        updated_role = cursor.fetchone()
        conn.commit()
        
        if updated_role:
            role = {"id": updated_role[0], "name": updated_role[1], "description": updated_role[2]}
        else:
            role = None
    except Exception as e:
        conn.rollback()
        print(f"Error updating role: {e}")
        role = None
    finally:
        cursor.close()
        conn.close()
        
    return role

def delete_role(role_id: int):
    """
    Delete a role
    """
    conn = db.get_connection()
    cursor = conn.cursor()
    
    try:
        # Check if it's a default role
        cursor.execute("SELECT name FROM roles WHERE id = %s", (role_id,))
        role = cursor.fetchone()
        
        if role and role[0] in ["user", "moderator", "admin"]:
            cursor.close()
            conn.close()
            return False, "Cannot delete default roles"
        
        cursor.execute("DELETE FROM roles WHERE id = %s", (role_id,))
        conn.commit()
        success = cursor.rowcount > 0
    except Exception as e:
        conn.rollback()
        print(f"Error deleting role: {e}")
        success = False
    finally:
        cursor.close()
        conn.close()
        
    return success, None if success else "Role not found or could not be deleted"

def get_all_permissions():
    """
    Retrieve all permissions from the database
    """
    conn = db.get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, name, description FROM permissions")
    permissions = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return [{"id": perm[0], "name": perm[1], "description": perm[2]} for perm in permissions]

def get_permissions_by_role_id(role_id: int):
    """
    Retrieve all permissions for a specific role
    """
    conn = db.get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT p.id, p.name, p.description 
        FROM permissions p
        JOIN role_permissions rp ON p.id = rp.permission_id
        WHERE rp.role_id = %s
    """, (role_id,))
    
    permissions = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return [{"id": perm[0], "name": perm[1], "description": perm[2]} for perm in permissions]

def get_permissions_by_role_name(role_name: str):
    """
    Retrieve all permissions for a specific role by role name
    """
    role = get_role_by_name(role_name)
    if not role:
        return []
    
    return get_permissions_by_role_id(role["id"])

def add_permission_to_role(role_id: int, permission_id: int) -> Tuple[bool, Optional[str]]:
    """
    Add a permission to a role
    """
    conn = db.get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "INSERT INTO role_permissions (role_id, permission_id) VALUES (%s, %s)",
            (role_id, permission_id)
        )
        conn.commit()
        success = True
        message = None
    except Exception as e:
        conn.rollback()
        print(f"Error adding permission to role: {e}")
        success = False
        message = str(e)
    finally:
        cursor.close()
        conn.close()
    
    return success, message

def remove_permission_from_role(role_id: int, permission_id: int) -> Tuple[bool, Optional[str]]:
    """
    Remove a permission from a role
    """
    conn = db.get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "DELETE FROM role_permissions WHERE role_id = %s AND permission_id = %s",
            (role_id, permission_id)
        )
        conn.commit()
        success = cursor.rowcount > 0
        message = None if success else "Permission not assigned to this role"
    except Exception as e:
        conn.rollback()
        print(f"Error removing permission from role: {e}")
        success = False
        message = str(e)
    finally:
        cursor.close()
        conn.close()
    
    return success, message

def get_user_permissions(user_id: int) -> List[str]:
    """
    Get all permission names for a user based on their role
    """
    conn = db.get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT role FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    
    if not user:
        cursor.close()
        conn.close()
        return []
    
    role_name = user[0]
    
    cursor.execute("""
        SELECT p.name 
        FROM permissions p
        JOIN role_permissions rp ON p.id = rp.permission_id
        JOIN roles r ON rp.role_id = r.id
        WHERE r.name = %s
    """, (role_name,))
    
    permissions = [row[0] for row in cursor.fetchall()]
    
    cursor.close()
    conn.close()
    
    return permissions

def check_user_permission(user_id: int, permission_name: str) -> bool:
    """
    Check if a user has a specific permission
    """
    permissions = get_user_permissions(user_id)
    return permission_name in permissions 