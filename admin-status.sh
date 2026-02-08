#!/bin/bash
# Quick start script for admin-controlled security model

echo "=================================================="
echo "  Admin-Controlled Security - Quick Start Guide"
echo "=================================================="
echo ""

# Check if database is running
if ! docker ps | grep -q postgres; then
    echo "❌ PostgreSQL is not running!"
    echo "   Start it with: docker-compose up -d postgres"
    exit 1
fi

echo "✓ PostgreSQL is running"
echo ""

# Check if admin user exists
echo "Checking for admin user..."
ADMIN_COUNT=$(docker-compose exec -T postgres psql -U cryptouser -d cryptodb -t -c "SELECT COUNT(*) FROM users WHERE role='admin';" 2>/dev/null | tr -d ' ')

if [ "$ADMIN_COUNT" = "0" ] || [ -z "$ADMIN_COUNT" ]; then
    echo ""
    echo "⚠️  No admin user found!"
    echo ""
    echo "You need to create an admin user first."
    echo "Run: python create_admin.py"
    echo ""
    exit 1
fi

echo "✓ Admin user exists"
echo ""

# Show summary
echo "=================================================="
echo "  System Status"
echo "=================================================="
echo ""

USER_COUNT=$(docker-compose exec -T postgres psql -U cryptouser -d cryptodb -t -c "SELECT COUNT(*) FROM users;" 2>/dev/null | tr -d ' ')
ADMIN_COUNT=$(docker-compose exec -T postgres psql -U cryptouser -d cryptodb -t -c "SELECT COUNT(*) FROM users WHERE role='admin';" 2>/dev/null | tr -d ' ')
PENDING_LOGINS=$(docker-compose exec -T postgres psql -U cryptouser -d cryptodb -t -c "SELECT COUNT(*) FROM pending_logins WHERE status='pending';" 2>/dev/null | tr -d ' ')
PENDING_DEVICES=$(docker-compose exec -T postgres psql -U cryptouser -d cryptodb -t -c "SELECT COUNT(*) FROM pending_device_auth WHERE status='pending';" 2>/dev/null | tr -d ' ')

echo "Total Users:       $USER_COUNT"
echo "Admin Users:       $ADMIN_COUNT"
echo "Pending Logins:    $PENDING_LOGINS"
echo "Pending Devices:   $PENDING_DEVICES"
echo ""

echo "=================================================="
echo "  Quick Commands"
echo "=================================================="
echo ""
echo "Create Admin User:"
echo "  python create_admin.py"
echo ""
echo "Start Application:"
echo "  docker-compose up"
echo ""
echo "Run Tests:"
echo "  python test_admin_security.py admin@example.com password"
echo ""
echo "View Logs:"
echo "  docker-compose logs -f backend"
echo ""
echo "Access API Docs:"
echo "  http://localhost:3001/docs"
echo ""

echo "=================================================="
echo "  Admin Endpoints (Require Admin Login)"
echo "=================================================="
echo ""
echo "POST /api/auth/admin/create-user"
echo "  → Create new user account"
echo ""
echo "GET /api/auth/admin/pending-logins"
echo "  → List all pending login requests"
echo ""
echo "POST /api/auth/admin/approve-login/{id}"
echo "  → Approve or reject a login request"
echo ""
echo "GET /api/auth/admin/pending-devices"
echo "  → List all pending device authorizations"
echo ""
echo "POST /api/auth/admin/approve-device/{id}"
echo "  → Approve or reject a device"
echo ""

echo "=================================================="
echo "  User Workflow"
echo "=================================================="
echo ""
echo "1. Admin creates user account"
echo "2. User attempts login → Creates pending request"
echo "3. Admin approves login"
echo "4. User logs in successfully"
echo "5. If new device → Admin approves device"
echo "6. User accesses documents"
echo "7. If viewing other's docs → Owner/Admin approves"
echo ""

echo "=================================================="

if [ "$PENDING_LOGINS" != "0" ] || [ "$PENDING_DEVICES" != "0" ]; then
    echo ""
    echo "⚠️  You have pending approvals!"
    echo "   Log in as admin to process them."
    echo ""
fi
