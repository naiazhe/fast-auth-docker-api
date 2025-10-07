# main.py
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

# --- 1. Import all authentication logic from auth.py ---
# This is the key to fixing the login issue.
from auth import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    User,
    authenticate_user,
    create_access_token,
    fake_users_db,
    get_current_active_user,
)
from datetime import timedelta

# --- 2. FastAPI Application and Endpoints ---
# The endpoints now use the imported functions.

app = FastAPI(title="Authentication Demo", version="1.0.0")

@app.get("/")
async def root():
    return {"message": "Welcome to the Authentication Demo"}

@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """Authenticate user and return access token."""
    # This now calls the function from auth.py, using the correct password hash
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    """Get current user's information."""
    return current_user

@app.get("/protected")
async def protected_route(current_user: User = Depends(get_current_active_user)):
    """An example of a protected route."""
    return {"message": f"Hello {current_user.full_name}, welcome to the protected area!"}