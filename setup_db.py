from sqlalchemy.orm import Session
from database import SessionLocal, engine, Base
import crud

# Create tables
Base.metadata.create_all(bind=engine)

def init_db():
    db = SessionLocal()
    try:
        # Create default roles if they don't exist
        if not crud.get_role_by_name(db, "user"):
            crud.create_role(db, "user", "Regular user")
        if not crud.get_role_by_name(db, "admin"):
            crud.create_role(db, "admin", "Administrator")
        if not crud.get_role_by_name(db, "moderator"):
            crud.create_role(db, "moderator", "Moderator")
        print("Database initialized successfully!")
    finally:
        db.close()

if __name__ == "__main__":
    init_db()