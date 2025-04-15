import psycopg2
from dotenv import load_dotenv
import os

# Load environment variables from .env
load_dotenv()

# Fetch variables
USER = os.getenv("USER")
PASSWORD = os.getenv("PASSWORD")
HOST = os.getenv("HOST")
PORT = os.getenv("PORT")
DBNAME = os.getenv("DBNAME")

# Establish the database connection
def get_connection():
    try:
        connection = psycopg2.connect(
            user=USER,
            password=PASSWORD,
            host=HOST,
            port=PORT,
            dbname=DBNAME
        )
        print("Database connection established successfully!")
        return connection
    except psycopg2.OperationalError as oe:
        print(f"Operational error: {oe}")
        raise
    except Exception as e:
        print(f"Failed to connect to the database: {e}")
        raise

def initialize_tables():
    """
    Initialize all required tables in the database
    """
    connection = get_connection()
    cursor = connection.cursor()
    
    try:
        # Create users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                full_name VARCHAR(100) NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                profile TEXT,
                role VARCHAR(20) NOT NULL DEFAULT 'user'
            )
        """)
        
        # Create user_sessions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_sessions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                token VARCHAR(255) NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create roles table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS roles (
                id SERIAL PRIMARY KEY,
                name VARCHAR(50) UNIQUE NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create permissions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS permissions (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) UNIQUE NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create role_permissions join table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS role_permissions (
                id SERIAL PRIMARY KEY,
                role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
                permission_id INTEGER REFERENCES permissions(id) ON DELETE CASCADE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(role_id, permission_id)
            )
        """)
        
        # Insert default roles if they don't exist
        cursor.execute("""
            INSERT INTO roles (name, description)
            VALUES
                ('user', 'Regular user with basic permissions'),
                ('moderator', 'User with elevated permissions to moderate content'),
                ('admin', 'Administrator with full system access')
            ON CONFLICT (name) DO NOTHING
        """)
        
        # Insert default permissions
        cursor.execute("""
            INSERT INTO permissions (name, description)
            VALUES
                ('read_own_profile', 'Can read own profile'),
                ('update_own_profile', 'Can update own profile'),
                ('delete_own_profile', 'Can delete own profile'),
                ('read_any_profile', 'Can read any user profile'),
                ('update_any_profile', 'Can update any user profile'),
                ('delete_any_profile', 'Can delete any user profile'),
                ('manage_roles', 'Can manage roles'),
                ('read_permissions', 'Can view permissions'),
                ('update_permissions', 'Can update permissions')
            ON CONFLICT (name) DO NOTHING
        """)
        
        # Assign default permissions to roles
        # First get role IDs
        cursor.execute("SELECT id, name FROM roles")
        role_ids = {row[1]: row[0] for row in cursor.fetchall()}
        
        # Then get permission IDs
        cursor.execute("SELECT id, name FROM permissions")
        permission_ids = {row[1]: row[0] for row in cursor.fetchall()}
        
        # Assign permissions to user role
        user_permissions = ['read_own_profile', 'update_own_profile', 'delete_own_profile']
        for perm in user_permissions:
            cursor.execute("""
                INSERT INTO role_permissions (role_id, permission_id)
                VALUES (%s, %s)
                ON CONFLICT (role_id, permission_id) DO NOTHING
            """, (role_ids['user'], permission_ids[perm]))
        
        # Assign permissions to moderator role
        moderator_permissions = user_permissions + ['read_any_profile']
        for perm in moderator_permissions:
            cursor.execute("""
                INSERT INTO role_permissions (role_id, permission_id)
                VALUES (%s, %s)
                ON CONFLICT (role_id, permission_id) DO NOTHING
            """, (role_ids['moderator'], permission_ids[perm]))
        
        # Assign all permissions to admin role
        for perm_id in permission_ids.values():
            cursor.execute("""
                INSERT INTO role_permissions (role_id, permission_id)
                VALUES (%s, %s)
                ON CONFLICT (role_id, permission_id) DO NOTHING
            """, (role_ids['admin'], perm_id))
        
        connection.commit()
        print("All tables initialized successfully!")
    except Exception as e:
        connection.rollback()
        print(f"Error initializing tables: {e}")
        raise
    finally:
        cursor.close()
        connection.close()

if __name__ == "__main__":
    # Initialize tables when this script is run directly
    initialize_tables()
