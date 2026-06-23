"""
Create superadmin user for matthunder
"""
import asyncio
import sys
from sqlalchemy import select
from app.database import async_session, init_db
from app.models import User
from app.core.security import get_password_hash


async def create_superadmin():
    """Create superadmin user"""
    await init_db()
    
    async with async_session() as db:
        # Check if superadmin already exists
        result = await db.execute(select(User).where(User.username == "admin"))
        existing = result.scalar_one_or_none()
        
        if existing:
            # Update to superuser and fix email if needed
            existing.is_superuser = True
            existing.is_active = True
            if existing.email.endswith('.local'):
                existing.email = "admin@matthunder.com"
            await db.commit()
            print("✓ Updated existing 'admin' user to superadmin")
            print(f"  Username: admin")
            print(f"  Email: {existing.email}")
            print(f"  Password: admin123 (unchanged)")
            return
        
        # Create new superadmin
        superadmin = User(
            username="admin",
            email="admin@matthunder.com",
            hashed_password=get_password_hash("admin123"),
            is_active=True,
            is_superuser=True
        )
        
        db.add(superadmin)
        await db.commit()
        await db.refresh(superadmin)
        
        print("✓ Superadmin created successfully!")
        print(f"  Username: admin")
        print(f"  Email: admin@matthunder.com")
        print(f"  Password: admin123")
        print(f"  User ID: {superadmin.id}")
        print("\n⚠️  Change the password after first login!")


if __name__ == "__main__":
    asyncio.run(create_superadmin())
