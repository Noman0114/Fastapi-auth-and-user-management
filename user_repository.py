import db
from passlib.context import CryptContext

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user_by_email(email: str):
    """
    Retrieve a user by email
    """
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, full_name, email, password, profile, role 
        FROM users 
        WHERE email = %s
    """, (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if user:
        return {
            "id": user[0],
            "full_name": user[1],
            "email": user[2],
            "password": user[3],
            "profile": user[4],
            "role": user[5]
        }
    return None

def create_user(full_name: str, email: str, password: str):
    """
    Create a new user
    """
    conn = db.get_connection()
    cursor = conn.cursor()
    
    # Check if user already exists
    cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
    if cursor.fetchone():
        cursor.close()
        conn.close()
        return None
    
    hashed_password = get_password_hash(password)
    
    cursor.execute("""
        INSERT INTO users (full_name, email, password) 
        VALUES (%s, %s, %s) 
        RETURNING id, full_name, email, profile, role
    """, (full_name, email, hashed_password))
    
    user = cursor.fetchone()
    conn.commit()
    cursor.close()
    conn.close()
    
    if user:
        return {
            "id": user[0],
            "full_name": user[1],
            "email": user[2],
            "profile": user[3],
            "role": user[4]
        }
    return None

def update_user(user_id: int, data: dict):
    """
    Update user information
    """
    conn = db.get_connection()
    cursor = conn.cursor()
    
    # Check if user exists
    cursor.execute("SELECT id FROM users WHERE id = %s", (user_id,))
    if not cursor.fetchone():
        cursor.close()
        conn.close()
        return None
    
    # Build update query dynamically based on provided fields
    update_parts = []
    params = []
    
    if 'full_name' in data and data['full_name']:
        update_parts.append("full_name = %s")
        params.append(data['full_name'])
    
    if 'email' in data and data['email']:
        update_parts.append("email = %s")
        params.append(data['email'])
    
    if 'password' in data and data['password']:
        update_parts.append("password = %s")
        params.append(get_password_hash(data['password']))
    
    if 'profile' in data and data['profile'] is not None:
        update_parts.append("profile = %s")
        params.append(data['profile'])
    
    if not update_parts:
        cursor.close()
        conn.close()
        return get_user_by_id(user_id)
    
    query = f"""
        UPDATE users 
        SET {', '.join(update_parts)} 
        WHERE id = %s 
        RETURNING id, full_name, email, profile, role
    """
    params.append(user_id)
    
    cursor.execute(query, params)
    updated_user = cursor.fetchone()
    conn.commit()
    cursor.close()
    conn.close()
    
    if updated_user:
        return {
            "id": updated_user[0],
            "full_name": updated_user[1],
            "email": updated_user[2],
            "profile": updated_user[3],
            "role": updated_user[4]
        }
    return None

def delete_user(user_id: int):
    """
    Delete a user
    """
    conn = db.get_connection()
    cursor = conn.cursor()
    
    # Check if user exists
    cursor.execute("SELECT id FROM users WHERE id = %s", (user_id,))
    if not cursor.fetchone():
        cursor.close()
        conn.close()
        return False
    
    cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit()
    cursor.close()
    conn.close()
    return True

def get_user_by_id(user_id: int):
    """
    Retrieve a user by ID
    """
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, full_name, email, profile, role 
        FROM users 
        WHERE id = %s
    """, (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if user:
        return {
            "id": user[0],
            "full_name": user[1],
            "email": user[2],
            "profile": user[3],
            "role": user[4]
        }
    return None

def get_all_users():
    """
    Retrieve all users
    """
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, full_name, email, profile, role 
        FROM users
    """)
    users = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return [
        {
            "id": user[0],
            "full_name": user[1],
            "email": user[2],
            "profile": user[3],
            "role": user[4]
        }
        for user in users
    ]

def update_user_role(user_id: int, new_role: str):
    """
    Update a user's role (for admin use)
    """
    conn = db.get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        UPDATE users 
        SET role = %s 
        WHERE id = %s 
        RETURNING id, full_name, email, profile, role
    """, (new_role, user_id))
    
    updated_user = cursor.fetchone()
    conn.commit()
    cursor.close()
    conn.close()
    
    if updated_user:
        return {
            "id": updated_user[0],
            "full_name": updated_user[1],
            "email": updated_user[2],
            "profile": updated_user[3],
            "role": updated_user[4]
        }
    return None 