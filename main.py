from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import timedelta

import user_repository
import auth
import db
import rbac_repository
from authorization import ROLES, PERMISSIONS

app = FastAPI(title="User Profile Management API", 
              description="API for user profile management with JWT authentication")

# Initialize database tables on startup
@app.on_event("startup")
async def startup_db_client():
    db.initialize_tables()

# Pydantic models
class UserBase(BaseModel):
    email: EmailStr
    full_name: str

class UserCreate(UserBase):
    password: str

class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    email: Optional[EmailStr] = None
    password: Optional[str] = None
    profile: Optional[str] = None

class User(UserBase):
    id: int
    profile: Optional[str] = None
    role: str

    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str

class RoleCreate(BaseModel):
    name: str
    description: Optional[str] = None

class RoleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None

class Role(BaseModel):
    id: int
    name: str
    description: Optional[str] = None

class Permission(BaseModel):
    id: int
    name: str
    description: Optional[str] = None

class RolePermission(BaseModel):
    role_id: int
    permission_id: int

# API endpoints
@app.get("/")
async def root():
    return {"message": "Advanced FastAPI Service with AI Integration"}


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await auth.authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create access token with user ID and role
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user["email"], "user_id": user["id"], "role": user["role"]},
        expires_delta=access_token_expires,
    )
    
    # Store token in database
    from datetime import datetime
    expires_at = datetime.utcnow() + timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    auth.store_token(user["id"], access_token, expires_at)
    
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/logout")
async def logout(current_user = Depends(auth.get_current_user), token: str = Depends(auth.oauth2_scheme)):
    # Invalidate token
    success = auth.invalidate_token(token)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to logout"
        )
    
    return {"message": "Successfully logged out"}

@app.post("/users/", response_model=User, status_code=status.HTTP_201_CREATED)
async def register_user(user: UserCreate):
    db_user = user_repository.get_user_by_email(user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    return user_repository.create_user(user.full_name, user.email, user.password)

# Development endpoint to create admin user
@app.post("/dev/create-admin", response_model=User, status_code=status.HTTP_201_CREATED)
async def create_admin_user(user: UserCreate):
    # Check if user exists
    db_user = user_repository.get_user_by_email(user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    created_user = user_repository.create_user(user.full_name, user.email, user.password)
    if not created_user:
        raise HTTPException(status_code=500, detail="Failed to create user")
    
    # Update to admin role
    admin_user = user_repository.update_user_role(created_user["id"], "admin")
    if not admin_user:
        raise HTTPException(status_code=500, detail="Failed to set admin role")
    
    return admin_user

@app.get("/users/me/", response_model=User)
async def read_users_me(current_user = Depends(auth.get_current_user)):
    # Authorize using Oso
    auth.authorize_user(current_user["id"], current_user["role"], "read_own_profile", None, current_user["id"])
    return current_user

@app.put("/users/me/", response_model=User)
async def update_user_me(user_data: UserUpdate, current_user = Depends(auth.get_current_user)):
    # Authorize using Oso
    auth.authorize_user(current_user["id"], current_user["role"], "update_own_profile", None, current_user["id"])
    
    # Create dictionary of update data
    update_data = user_data.dict(exclude_unset=True)
    
    # Hash password if it's in the update data
    if "password" in update_data:
        update_data["password"] = auth.get_password_hash(update_data["password"])
    
    # Update user
    updated_user = user_repository.update_user(current_user["id"], update_data)
    if not updated_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return updated_user

@app.delete("/users/me/", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user_me(current_user = Depends(auth.get_current_user)):
    # Authorize using Oso
    auth.authorize_user(current_user["id"], current_user["role"], "delete_own_profile", None, current_user["id"])
    
    # Delete user
    deleted = user_repository.delete_user(current_user["id"])
    if not deleted:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"message": "User deleted successfully"}

@app.get("/users/{user_id}", response_model=User)
async def read_user(
    user_id: int, 
    current_user = Depends(auth.get_current_user)
):
    # Check if user is requesting their own data
    if current_user["id"] == user_id:
        auth.authorize_user(current_user["id"], current_user["role"], "read_own_profile", user_id, user_id)
    else:
        # For others' profiles, need read_any_profile permission
        auth.authorize_user(current_user["id"], current_user["role"], "read_any_profile", user_id, None)
    
    # Get user by ID
    user = user_repository.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return user

@app.get("/users/", response_model=List[User])
async def read_users(current_user = Depends(auth.get_current_user)):
    # Only users with read_any_profile permission can get all users
    auth.authorize_user(current_user["id"], current_user["role"], "read_any_profile")
    
    return user_repository.get_all_users()

@app.put("/users/{user_id}/role", response_model=User)
async def update_user_role(
    user_id: int, 
    role: str, 
    current_user = Depends(auth.get_current_user)
):
    # Check if user has permission to manage roles
    auth.authorize_user(current_user["id"], current_user["role"], "manage_roles")
    
    # Check if role is valid
    if role not in ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role. Valid roles are: {', '.join(ROLES.keys())}")
    
    # Update user role
    updated_user = user_repository.update_user_role(user_id, role)
    if not updated_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return updated_user

# RBAC Endpoints for roles and permissions
@app.get("/rbac/roles", response_model=List[Role])
async def get_roles(current_user = Depends(auth.get_current_user)):
    # Only users with manage_roles permission can view roles
    auth.authorize_user(current_user["id"], current_user["role"], "manage_roles")
    
    return rbac_repository.get_all_roles()

@app.post("/rbac/roles", response_model=Role, status_code=status.HTTP_201_CREATED)
async def create_role(role: RoleCreate, current_user = Depends(auth.get_current_user)):
    # Only users with manage_roles permission can create roles
    auth.authorize_user(current_user["id"], current_user["role"], "manage_roles")
    
    # Check if role name already exists
    if rbac_repository.get_role_by_name(role.name):
        raise HTTPException(status_code=400, detail="Role name already exists")
    
    created_role = rbac_repository.create_role(role.name, role.description)
    if not created_role:
        raise HTTPException(status_code=500, detail="Failed to create role")
    
    return created_role

@app.put("/rbac/roles/{role_id}", response_model=Role)
async def update_role(
    role_id: int,
    role_data: RoleUpdate,
    current_user = Depends(auth.get_current_user)
):
    # Only users with manage_roles permission can update roles
    auth.authorize_user(current_user["id"], current_user["role"], "manage_roles")
    
    # Update role
    update_data = role_data.dict(exclude_unset=True)
    updated_role = rbac_repository.update_role(role_id, update_data)
    
    if not updated_role:
        raise HTTPException(status_code=404, detail="Role not found")
    
    return updated_role

@app.delete("/rbac/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role(role_id: int, current_user = Depends(auth.get_current_user)):
    # Only users with manage_roles permission can delete roles
    auth.authorize_user(current_user["id"], current_user["role"], "manage_roles")
    
    # Delete role
    success, message = rbac_repository.delete_role(role_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST if message else status.HTTP_404_NOT_FOUND,
            detail=message or "Role not found"
        )
    
    return {"message": "Role deleted successfully"}

@app.get("/rbac/permissions", response_model=List[Permission])
async def get_permissions(current_user = Depends(auth.get_current_user)):
    # Only users with read_permissions permission can view permissions
    auth.authorize_user(current_user["id"], current_user["role"], "read_permissions")
    
    return rbac_repository.get_all_permissions()

@app.get("/rbac/roles/{role_id}/permissions", response_model=List[Permission])
async def get_role_permissions(role_id: int, current_user = Depends(auth.get_current_user)):
    # Only users with read_permissions permission can view role permissions
    auth.authorize_user(current_user["id"], current_user["role"], "read_permissions")
    
    return rbac_repository.get_permissions_by_role_id(role_id)

@app.post("/rbac/roles/{role_id}/permissions", status_code=status.HTTP_201_CREATED)
async def add_permission_to_role(
    role_id: int,
    permission_id: int,
    current_user = Depends(auth.get_current_user)
):
    # Only users with update_permissions permission can add permissions
    auth.authorize_user(current_user["id"], current_user["role"], "update_permissions")
    
    # Add permission to role
    success, message = rbac_repository.add_permission_to_role(role_id, permission_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message or "Failed to add permission to role"
        )
    
    return {"message": "Permission added to role successfully"}

@app.delete("/rbac/roles/{role_id}/permissions/{permission_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_permission_from_role(
    role_id: int,
    permission_id: int,
    current_user = Depends(auth.get_current_user)
):
    # Only users with update_permissions permission can remove permissions
    auth.authorize_user(current_user["id"], current_user["role"], "update_permissions")
    
    # Remove permission from role
    success, message = rbac_repository.remove_permission_from_role(role_id, permission_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST if message else status.HTTP_404_NOT_FOUND,
            detail=message or "Permission not found for this role"
        )
    
    return {"message": "Permission removed from role successfully"}

@app.get("/rbac/my-permissions", response_model=List[str])
async def get_my_permissions(current_user = Depends(auth.get_current_user)):
    # Any authenticated user can view their own permissions
    permissions = rbac_repository.get_user_permissions(current_user["id"])
    return permissions

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

