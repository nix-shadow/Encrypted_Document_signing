"""
Simplified tests for authentication.
"""

import pytest


class TestCSRFToken:
    """Test CSRF token functionality."""
    
    def test_get_csrf_token(self, client):
        """Test CSRF token generation."""
        response = client.get("/api/auth/csrf-token")
        assert response.status_code == 200
        data = response.json()
        assert "csrf_token" in data
        assert len(data["csrf_token"]) > 0
    
    def test_csrf_tokens_are_unique(self, client):
        """Test that CSRF tokens are unique."""
        response1 = client.get("/api/auth/csrf-token")
        response2 = client.get("/api/auth/csrf-token")
        
        token1 = response1.json()["csrf_token"]
        token2 = response2.json()["csrf_token"]
        
        assert token1 != token2


class TestAdminUserCreation:
    """Test admin user creation endpoint."""
    
    def test_admin_create_user_without_csrf_token(self, client):
        """Test that user creation without CSRF token fails."""
        response = client.post(
            "/api/auth/admin/create-user",
            json={
                "email": "test@example.com",
                "password": "SecurePass123!",
                "role": "user"
            }
        )
        # Should fail - either 401 (no auth) or 403 (no CSRF)
        assert response.status_code in [401, 403]


class TestUserLogin:
    """Test user login."""
    
    def test_login_nonexistent_user(self, client):
        """Test login with non-existent user."""
        csrf_response = client.get("/api/auth/csrf-token")
        csrf_token = csrf_response.json()["csrf_token"]
        
        response = client.post(
            "/api/auth/login",
            json={
                "email": "nonexistent@example.com",
                "password": "WrongPass123!",
                "device_fingerprint": "test-device"
            },
            headers={"X-CSRF-Token": csrf_token}
        )
        
        assert response.status_code == 401


class TestLogout:
    """Test logout functionality."""
    
    def test_logout_without_session(self, client):
        """Test that logout without session returns appropriate response."""
        response = client.post("/api/auth/logout")
        # Can be 200 (logout always succeeds) or 401 (no session)
        assert response.status_code in [200, 401]


class TestSessionManagement:
    """Test session management."""
    
    def test_protected_endpoint_without_session(self, client):
        """Test that protected endpoints require authentication."""
        response = client.get("/api/documents/")
        assert response.status_code == 401
