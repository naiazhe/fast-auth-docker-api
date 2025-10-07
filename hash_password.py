# hash_password.py
from passlib.context import CryptContext

# Use the same context as your main application
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

plain_password = "secret"
hashed_password = pwd_context.hash(plain_password)

print(f"New hashed password: {hashed_password}")