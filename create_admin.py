#!/usr/bin/env python3
"""
Create initial admin user for the Encrypted Document Signing Platform.

This script should be run once during initial setup to create the first admin account.
After the first admin is created, additional users can be created through the API.

Usage:
    python create_admin.py
"""

import sys
import os
from datetime import datetime

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from backend.app.db import SessionLocal
from backend.app.models import User, UserRole
from backend.app import crypto
from backend.app.security import hash_password
from backend.app.services.audit_service import create_audit_log


def create_admin_user(email: str, password: str):
    """Create an admin user with the given credentials."""
    
    db = SessionLocal()
    try:
        # Check if admin already exists
        existing = db.query(User).filter(User.email == email).first()
        if existing:
            print(f"❌ Error: User with email {email} already exists!")
            return False
        
        # Check if any admin exists
        existing_admin = db.query(User).filter(User.role == UserRole.ADMIN).first()
        if existing_admin:
            print(f"⚠️  Warning: An admin user already exists ({existing_admin.email})")
            response = input("Do you want to create another admin? (yes/no): ")
            if response.lower() not in ['yes', 'y']:
                print("Aborted.")
                return False
        
        print(f"Creating admin user: {email}")
        print("Generating RSA keypair (2048-bit)...")
        
        # Generate RSA keypair
        public_key, private_key = crypto.generate_rsa_keypair(key_size=2048)
        
        # Encrypt private key with password
        print("Encrypting private key...")
        encrypted_private = crypto.encrypt_private_key(private_key, password)
        
        # Hash password
        print("Hashing password...")
        password_hash = hash_password(password)
        
        # Create user
        user = User(
            email=email,
            password_hash=password_hash,
            public_key_pem=public_key,
            private_key_encrypted=encrypted_private,
            role=UserRole.ADMIN,
            is_approved=True,  # Admin is auto-approved
            approved_at=datetime.utcnow()
        )
        
        db.add(user)
        db.commit()
        db.refresh(user)
        
        # Create audit log
        create_audit_log(
            db, user.id, "admin.created", "user", user.id,
            "Initial admin user created"
        )
        
        print(f"✅ Admin user created successfully!")
        print(f"   Email: {email}")
        print(f"   User ID: {user.id}")
        print(f"   Role: {user.role.value}")
        print(f"\n⚠️  IMPORTANT: Keep your password safe!")
        print("   You can now log in to the platform with these credentials.")
        
        return True
        
    except Exception as e:
        print(f"❌ Error creating admin user: {e}")
        db.rollback()
        return False
    finally:
        db.close()


def main():
    """Main function to prompt for admin credentials and create user."""
    
    print("=" * 60)
    print("  Encrypted Document Signing Platform - Admin Setup")
    print("=" * 60)
    print()
    
    # Get email
    while True:
        email = input("Enter admin email: ").strip()
        if not email:
            print("❌ Email cannot be empty!")
            continue
        if "@" not in email:
            print("❌ Invalid email format!")
            continue
        break
    
    # Get password
    import getpass
    while True:
        password = getpass.getpass("Enter admin password: ")
        if len(password) < 8:
            print("❌ Password must be at least 8 characters!")
            continue
        
        password_confirm = getpass.getpass("Confirm password: ")
        if password != password_confirm:
            print("❌ Passwords do not match!")
            continue
        
        break
    
    print()
    
    # Create admin
    success = create_admin_user(email, password)
    
    if success:
        print()
        print("Next steps:")
        print("1. Start the application: docker-compose up")
        print("2. Log in with your admin credentials")
        print("3. Create additional users via /api/auth/admin/create-user")
        print()
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
