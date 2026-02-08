# Admin-Controlled Security Model Implementation

## ✅ COMPLETED CHANGES

### 1. Database Models Updated (`backend/app/models.py`)
- ✅ Added `UserRole` enum (ADMIN, USER)
- ✅ Added `ApprovalStatus` enum (PENDING, APPROVED, REJECTED)
- ✅ Updated `User` model with:
  - `role` field (admin/user)
  - `is_approved` field (requires admin approval)
  - `approved_by` field (tracks who approved)
  - `approved_at` timestamp
- ✅ Updated `PendingDeviceAuth` with approval workflow fields
- ✅ Added `PendingLogin` model for login approval workflow
- ✅ Added `ViewingSession` model for document viewing tracking

### 2. Database Schema Updated (`migrations/init_db.sql`)
- ✅ Created ENUM types for `user_role` and `approval_status`
- ✅ Updated `users` table with role and approval fields
- ✅ Updated `pending_device_auth` table with approval fields
- ✅ Created `pending_logins` table
- ✅ Created `viewing_sessions` table
- ✅ Added indexes for performance

### 3. Authentication Schemas Updated (`backend/app/schemas.py`)
- ✅ Added `AdminCreateUserRequest` schema
- ✅ Added `AdminUserResponse` schema
- ✅ Added `PendingLoginResponse` schema
- ✅ Added `PendingDeviceResponse` schema
- ✅ Added `ViewingSessionResponse` schema
- ✅ Added `ApprovalRequest` schema
- ✅ Added `LoginPollResponse` schema

### 4. Dependencies Updated (`backend/app/deps.py`)
- ✅ Added approval check in `get_current_user()`
- ✅ Added `get_admin_user()` dependency for admin-only endpoints
- ✅ Imported `UserRole` for role checking

### 5. User Service Updated (`backend/app/services/user_service.py`)
- ✅ Updated `create_user()` to accept `role` parameter
- ✅ New users default to `is_approved=False`
- ✅ Imported `UserRole` enum

### 6. Authentication Router Updated (`backend/app/routers/auth.py`)
- ✅ **REMOVED** public `/register` endpoint
- ✅ Added `/admin/create-user` endpoint (admin only)
- ✅ Updated `/login` endpoint with:
  - Admin approval check
  - Device verification requirement
  - Pending login creation for non-admin users
  - Admin bypass for direct login
- ✅ Added `/login/status` endpoint for polling approval status
- ✅ Added `/admin/approve-login/{pending_id}` endpoint
- ✅ Added `/admin/approve-device/{pending_id}` endpoint
- ✅ Added `/admin/pending-logins` endpoint (list all pending)
- ✅ Added `/admin/pending-devices` endpoint (list all pending)

### 7. Documents Router Updated (`backend/app/routers/documents.py`)
- ✅ Added viewing session check in `GET /{document_id}`
- ✅ Non-admin, non-owner users require approval to view documents
- ✅ Added `/documents/{document_id}/viewing-sessions` endpoint
- ✅ Added `/documents/{document_id}/approve-viewer/{session_id}` endpoint
- ✅ Added `/documents/{document_id}/end-session/{session_id}` endpoint
- ✅ Real-time device monitoring for document viewers

### 8. Admin Setup Script Created (`create_admin.py`)
- ✅ Command-line tool to create first admin user
- ✅ Interactive prompts for email and password
- ✅ Checks for existing admin users
- ✅ Auto-approves admin accounts
- ✅ Creates audit log entry

## 🔒 SECURITY FEATURES IMPLEMENTED

### Zero-Trust Architecture
1. **No Public Registration** - Only admins can create accounts
2. **Login Approval** - All non-admin logins require admin approval
3. **Device Verification** - New devices must be approved by admin
4. **Document Viewing Approval** - Non-owners need approval to view documents
5. **Admin Bypass** - Admins can access system without approval delays

### Multi-Level Approval Workflows
- **User Creation**: Admin creates → Auto-approved
- **Device Authorization**: New device detected → Pending → Admin approves
- **Login Approval**: User logs in → Pending → Admin approves
- **Document Viewing**: User requests view → Pending → Owner/Admin approves

### Real-Time Monitoring
- **Active Viewing Sessions**: Track who is viewing each document
- **Device Tracking**: Monitor all devices accessing the system
- **Audit Logging**: All approvals/rejections logged

## 📋 API ENDPOINTS SUMMARY

### Admin Endpoints (Require Admin Role)
```
POST   /api/auth/admin/create-user           - Create new user
POST   /api/auth/admin/approve-login/:id     - Approve/reject login
POST   /api/auth/admin/approve-device/:id    - Approve/reject device
GET    /api/auth/admin/pending-logins        - List pending logins
GET    /api/auth/admin/pending-devices       - List pending devices
```

### User Endpoints
```
POST   /api/auth/login                       - Login (creates pending request)
GET    /api/auth/login/status?email=...      - Poll login approval status
POST   /api/auth/logout                      - Logout
```

### Document Endpoints (Owner/Admin)
```
GET    /api/documents/:id/viewing-sessions        - List active viewers
POST   /api/documents/:id/approve-viewer/:sid     - Approve/reject viewer
POST   /api/documents/:id/end-session/:sid        - End viewing session
```

## 🚀 USAGE FLOW

### Initial Setup
1. Run database migrations: `docker-compose up postgres`
2. Create admin user: `python create_admin.py`
3. Start application: `docker-compose up`

### Admin Creates User
```bash
POST /api/auth/admin/create-user
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "role": "user"
}
```

### User Login Flow (Non-Admin)
1. User attempts login → Creates pending login request
2. User polls `/api/auth/login/status?email=user@example.com`
3. Admin sees pending request in `/api/auth/admin/pending-logins`
4. Admin approves via `/api/auth/admin/approve-login/{id}`
5. User's next login attempt succeeds

### Device Authorization Flow
1. User logs in from new device → Device not trusted error
2. Pending device auth created automatically
3. Admin sees in `/api/auth/admin/pending-devices`
4. Admin approves via `/api/auth/admin/approve-device/{id}`
5. Device is now trusted

### Document Viewing Flow
1. User requests document → Viewing session created (pending)
2. Owner/Admin sees in `/api/documents/{id}/viewing-sessions`
3. Owner/Admin approves via `/api/documents/{id}/approve-viewer/{sid}`
4. User can now view document
5. Owner/Admin can end session anytime

## ⚠️ IMPORTANT NOTES

1. **First Admin**: Must be created using `create_admin.py` script
2. **Admin Powers**: Admins bypass all approval workflows
3. **Password Security**: Admin password cannot be reset without database access
4. **Session Expiry**: Pending logins expire after 15 minutes
5. **Device Expiry**: Pending device auths expire based on settings

## 🔄 MIGRATION REQUIRED

To apply these changes to existing database:

```bash
# Stop application
docker-compose down

# Backup database
docker-compose up -d postgres
docker exec -t postgres pg_dump -U cryptouser cryptodb > backup.sql

# Drop and recreate database
docker-compose exec postgres psql -U cryptouser -c "DROP DATABASE cryptodb;"
docker-compose exec postgres psql -U cryptouser -c "CREATE DATABASE cryptodb;"

# Run new migrations
docker-compose exec postgres psql -U cryptouser -d cryptodb < migrations/init_db.sql

# Create admin user
python create_admin.py

# Restart application
docker-compose up
```

## ✅ TESTING CHECKLIST

- [ ] Admin user creation works
- [ ] Admin can create new users
- [ ] Non-admin user login creates pending request
- [ ] Admin can approve/reject logins
- [ ] New device requires approval
- [ ] Admin can approve/reject devices
- [ ] Document viewing requires approval (non-owner, non-admin)
- [ ] Owner can approve viewers
- [ ] Admin can approve viewers
- [ ] Viewing sessions tracked correctly
- [ ] Admin can end viewing sessions
- [ ] Audit logs created for all actions

## 📝 NEXT STEPS

1. Update frontend to handle new approval workflows
2. Add email notifications for pending approvals
3. Add webhook support for approval events
4. Implement admin dashboard UI
5. Add batch approval functionality
6. Add approval expiry notifications
