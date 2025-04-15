# User Profile Management API with RBAC

A FastAPI application for user profile management with JWT authentication and Role-Based Access Control (RBAC).

## Features

- User registration and authentication with JWT
- Profile management (create, read, update, delete)
- Role-Based Access Control (RBAC)
- Permission management
- PostgreSQL database storage

## Role-Based Access Control (RBAC)

The application implements a custom RBAC system that controls access to endpoints based on user roles and permissions.

### Role Hierarchy

The system has three predefined roles with the following hierarchy:

- **user**: Basic user with limited permissions
- **moderator**: Includes all user permissions plus ability to view other profiles
- **admin**: Full access to all features including role and permission management

### Permissions

Available permissions in the system:

| Permission | Description | Available to Roles |
|------------|-------------|-------------------|
| read_own_profile | Can view own profile | user, moderator, admin |
| update_own_profile | Can update own profile | user, moderator, admin |
| delete_own_profile | Can delete own profile | user, moderator, admin |
| read_any_profile | Can view any user profile | moderator, admin |
| update_any_profile | Can update any user profile | admin |
| delete_any_profile | Can delete any user profile | admin |
| manage_roles | Can create, update, delete roles | admin |
| read_permissions | Can view permissions | admin |
| update_permissions | Can assign/remove permissions | admin |

## API Endpoints

### Authentication

- `POST /token`: Get access token
- `POST /logout`: Invalidate current token

### User Management

- `POST /users/`: Register new user
- `GET /users/me/`: Get current user profile
- `PUT /users/me/`: Update current user profile
- `DELETE /users/me/`: Delete current user account
- `GET /users/{user_id}`: Get a specific user (requires permissions)
- `GET /users/`: Get all users (requires permissions)
- `PUT /users/{user_id}/role`: Update a user's role (admin only)

### Role Management (Admin Only)

- `GET /rbac/roles`: Get all roles
- `POST /rbac/roles`: Create a new role
- `PUT /rbac/roles/{role_id}`: Update a role
- `DELETE /rbac/roles/{role_id}`: Delete a role

### Permission Management (Admin Only)

- `GET /rbac/permissions`: Get all permissions
- `GET /rbac/roles/{role_id}/permissions`: Get permissions for a role
- `POST /rbac/roles/{role_id}/permissions`: Add permission to role
- `DELETE /rbac/roles/{role_id}/permissions/{permission_id}`: Remove permission from role
- `GET /rbac/my-permissions`: Get permissions for current user

## Setup and Installation

### Prerequisites

- Python 3.8+
- PostgreSQL

### Installation Steps

1. Clone the repository:
   ```
   git clone <repository-url>
   cd <repository-directory>
   ```

2. Set up a virtual environment:
   ```
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Create a `.env` file with the following variables:
   ```
   USER=postgres_user
   PASSWORD=postgres_password
   HOST=localhost
   PORT=5432
   DBNAME=user_management
   JWT_SECRET_KEY=your_secure_jwt_secret
   ```

5. Initialize the database:
   ```
   python db.py
   ```

6. Run the application:
   ```
   uvicorn main:app --reload
   ```

7. Access the API documentation at `http://localhost:8000/docs`

## Using RBAC in Your Code

### Protecting an Endpoint with RBAC

To protect an endpoint with RBAC, use the `authorize` function from `authorization.py`:

```python
from authorization import authorize

@app.get("/protected-resource/{resource_id}")
async def get_protected_resource(
    resource_id: int,
    current_user = Depends(auth.get_current_user)
):
    # Check if user has permission
    authorize(
        user_id=current_user["id"],
        user_role=current_user["role"],
        action="read_any_profile",  # The required permission
        resource_id=resource_id,
        owner_id=None  # Set this to resource owner's ID if ownership matters
    )
    
    # If authorize doesn't raise an exception, the user has permission
    return {"message": "You have access to this resource"}
```

### Checking Ownership

For resources that should only be accessible to their owners (except for admins/moderators):

```python
@app.get("/user-resource/{resource_id}")
async def get_user_resource(
    resource_id: int,
    current_user = Depends(auth.get_current_user)
):
    # Get the resource owner
    resource = get_resource(resource_id)
    owner_id = resource["owner_id"]
    
    # If user is the owner, use "own" permission
    if current_user["id"] == owner_id:
        authorize(
            user_id=current_user["id"],
            user_role=current_user["role"],
            action="read_own_profile",
            resource_id=resource_id,
            owner_id=owner_id
        )
    else:
        # If user is not the owner, they need "any" permission
        authorize(
            user_id=current_user["id"],
            user_role=current_user["role"],
            action="read_any_profile",
            resource_id=resource_id,
            owner_id=owner_id
        )
    
    return resource
```

## Extending the RBAC System

### Adding New Roles

To add new roles, add them to the database using the role management endpoints. Default roles are initialized in `db.py`.

### Adding New Permissions

To add new permissions, modify the `PERMISSIONS` dictionary in `authorization.py` and update the database initialization in `db.py`.
