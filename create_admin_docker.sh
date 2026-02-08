#!/bin/bash
# Create admin user inside Docker container

echo "🔐 Creating Admin User..."
echo ""

docker-compose exec -T backend python << 'PYTHON_SCRIPT'
from app.db import SessionLocal
from app.models import User
from app.security import hash_password
from app.crypto.rsa_operations import generate_rsa_keypair
from app.crypto.key_manager import encrypt_private_key

db = SessionLocal()

# Check if admin exists
admin_email = 'admin@cryptosign.com'
admin = db.query(User).filter(User.email == admin_email).first()

if admin:
    print(f'❌ Admin user already exists: {admin_email}')
    print(f'   Role: {admin.role}')
    print(f'   Approved: {admin.is_approved}')
else:
    # Create admin
    password = 'Admin@123'
    public_key_pem, private_key_pem = generate_rsa_keypair()
    
    # Encrypt private key with password
    encrypted_private_key = encrypt_private_key(private_key_pem, password)
    
    admin = User(
        email=admin_email,
        password_hash=hash_password(password),
        public_key_pem=public_key_pem,
        private_key_encrypted=encrypted_private_key,
        role='admin',
        is_approved=True
    )
    
    db.add(admin)
    db.commit()
    
    print('✅ Admin user created successfully!')
    print('')
    print('Login Credentials:')
    print('==================')
    print(f'Email:    {admin_email}')
    print(f'Password: {password}')
    print('')
    print('⚠️  IMPORTANT: Change the password after first login!')
    print('')
    print('🌐 Login at: http://localhost:3000')

db.close()
PYTHON_SCRIPT

echo ""
echo "✅ Done!"
