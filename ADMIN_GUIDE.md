# Admin Dashboard Guide

## Admin Credentials

**Email:** `admin@example.com`  
**Password:** `Admin123!`

## Admin Endpoints

### 1. List All Users
Get a list of all users in the system.

```bash
GET /api/auth/admin/users
```

**Response:**
```json
[
  {
    "id": 11,
    "email": "admin@example.com",
    "role": "admin",
    "is_approved": true,
    "approved_at": "2026-02-07T15:45:47.338422",
    "created_at": "2026-02-07T15:45:47.341198"
  },
  {
    "id": 8,
    "email": "user@example.com",
    "role": "user",
    "is_approved": false,
    "approved_at": null,
    "created_at": "2026-02-07T15:33:26.655384"
  }
]
```

### 2. List Pending Users
Get users awaiting approval.

```bash
GET /api/auth/admin/pending-users
```

### 3. Approve User
Approve a pending user account.

```bash
POST /api/auth/admin/approve-user/{user_id}
```

**Example:**
```bash
curl -X POST 'http://localhost:3001/api/auth/admin/approve-user/8' \
  -H "X-CSRF-Token: YOUR_CSRF_TOKEN" \
  -b cookies.txt
```

**Response:**
```json
{
  "message": "User user@example.com approved successfully"
}
```

### 4. Reject User
Reject and delete a pending user account.

```bash
POST /api/auth/admin/reject-user/{user_id}
```

### 5. Delete User
Delete any user account (except admins).

```bash
DELETE /api/auth/admin/delete-user/{user_id}
```

### 6. Create User (Admin)
Create a new user with auto-approval.

```bash
POST /api/auth/admin/create-user
```

**Payload:**
```json
{
  "email": "newuser@example.com",
  "password": "SecurePassword123!",
  "role": "user"
}
```

### 7. Pending Login Approvals
View login requests awaiting approval.

```bash
GET /api/auth/admin/pending-logins
```

### 8. Approve Login
Approve a pending login request.

```bash
POST /api/auth/admin/approve-login/{pending_id}
```

### 9. Pending Device Approvals
View devices awaiting trust approval.

```bash
GET /api/auth/admin/pending-devices
```

### 10. Approve Device
Approve a device for trusted access.

```bash
POST /api/auth/admin/approve-device/{pending_id}
```

## Quick Start - Admin Login

### Step 1: Get CSRF Token
```bash
curl -X GET 'http://localhost:3001/api/auth/csrf-token' \
  -c cookies.txt | jq -r '.csrf_token' > csrf_token.txt
```

### Step 2: Login as Admin
```bash
curl -X POST 'http://localhost:3001/api/auth/login' \
  -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $(cat csrf_token.txt)" \
  -b cookies.txt -c cookies.txt \
  -d '{"email":"admin@example.com","password":"Admin123!"}'
```

### Step 3: Use Admin Endpoints
```bash
# List all users
curl -X GET 'http://localhost:3001/api/auth/admin/users' \
  -H "X-CSRF-Token: $(cat csrf_token.txt)" \
  -b cookies.txt

# List pending users
curl -X GET 'http://localhost:3001/api/auth/admin/pending-users' \
  -H "X-CSRF-Token: $(cat csrf_token.txt)" \
  -b cookies.txt

# Approve a user
curl -X POST 'http://localhost:3001/api/auth/admin/approve-user/USER_ID' \
  -H "X-CSRF-Token: $(cat csrf_token.txt)" \
  -b cookies.txt
```

## Frontend Integration

The admin dashboard features should be accessible at **http://localhost:3000** after logging in as admin.

The React frontend should detect the admin role and display:
- User management page
- Pending approvals list
- Device management
- Login approval queue
- Audit logs

## Testing the Admin Flow

### 1. Register a New User
```bash
curl -X POST 'http://localhost:3001/api/auth/register' \
  -H 'Content-Type: application/json' \
  -d '{"email":"testuser@example.com","password":"TestPass123!"}'
```

### 2. Try to Login (Will Fail - Pending Approval)
```bash
# User will get: "Your account is pending admin approval"
```

### 3. Admin Approves the User
```bash
# Admin logs in and approves user
curl -X POST 'http://localhost:3001/api/auth/admin/approve-user/USER_ID' \
  -H "X-CSRF-Token: $(cat csrf_token.txt)" \
  -b cookies.txt
```

### 4. User Can Now Login
```bash
# User can now successfully log in
```

## Database Direct Access (Development Only)

### Create Admin User via Docker
```bash
docker compose exec backend python -c "
from app.db import SessionLocal
from app.models import User
from app import crypto
from app.security import hash_password
from datetime import datetime

db = SessionLocal()
try:
    password = 'YourPassword123!'
    pub, priv = crypto.generate_rsa_keypair(2048)
    enc_priv = crypto.encrypt_private_key(priv, password)
    admin = User(
        email='admin@company.com',
        password_hash=hash_password(password),
        public_key_pem=pub,
        private_key_encrypted=enc_priv,
        role='admin',
        is_approved=True,
        approved_at=datetime.utcnow()
    )
    db.add(admin)
    db.commit()
    print(f'Admin created: {admin.email}')
finally:
    db.close()
"
```

## Security Notes

1. **Admin accounts bypass all approval workflows**
2. **Admins cannot delete other admins** (security measure)
3. **All admin actions are logged** in the audit_log table
4. **CSRF tokens are required** for all state-changing operations
5. **Session cookies are httpOnly** and should be secure (HTTPS in production)

## API Documentation

Full interactive API documentation is available at:
**http://localhost:3001/docs**

You can test all endpoints directly from the Swagger UI after logging in.
