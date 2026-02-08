"""
Unit and integration tests for authentication endpoints.

Tests cover:
- User registration
- User login
- Session management
- CSRF token generation
- Password validation
- Email validation
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.db import Base, get_db
from app.utils.csrf import csrf_tokens

# Test database setup
SQLALCHEMY_TEST_DATABASE_URL = "sqlite:///./test_auth.db"
engine = create_engine(SQLALCHEMY_TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    """Override database dependency for testing."""
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(scope="function")
def client():
    """Create test client and database tables."""
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as test_client:
        yield test_client
    Base.metadata.drop_all(bind=engine)
    csrf_tokens.clear()


class TestCSRFToken:
    """Test CSRF token generation."""
    
    def test_get_csrf_token(self, client):
        """Test that CSRF token endpoint returns a valid token."""
        response = client.get("/api/auth/csrf-token")
        assert response.status_code == 200
        data = response.json()
        assert "csrf_token" in data
        assert isinstance(data["csrf_token"], str)
        assert len(data["csrf_token"]) > 0
    
    def test_csrf_tokens_are_unique(self, client):
        """Test that multiple CSRF tokens are unique."""
        response1 = client.get("/api/auth/csrf-token")
        response2 = client.get("/api/auth/csrf-token")
        token1 = response1.json()["csrf_token"]
        token2 = response2.json()["csrf_token"]
        assert token1 != token2


@pytest.mark.skip(reason="Registration endpoint removed - admin-controlled user creation only")
class TestUserRegistration:
    """Test user registration functionality."""
    
    def test_register_success(self, client):
        """Test successful user registration."""
        # Get CSRF token
        csrf_response = client.get("/api/auth/csrf-token")
        csrf_token = csrf_response.json()["csrf_token"]
        
        # Register user
        response = client.post(
            "/auth/register",
            json={"email": "test@example.com", "password": "SecurePass123!"},
            headers={"X-CSRF-Token": csrf_token}
        )
        assert response.status_code == 201
        data = response.json()
        assert data["email"] == "test@example.com"
        assert "id" in data
        assert "public_key" in data
        assert "password_hash" not in data  # Should not expose password hash
    
    def test_register_duplicate_email(self, client):
        """Test that registering with duplicate email fails."""
        csrf_response = client.get("/api/auth/csrf-token")
        csrf_token = csrf_response.json()["csrf_token"]
        
        # Register first user
        client.post(
            "/auth/register",
            json={"email": "test@example.com", "password": "SecurePass123!"},
            headers={"X-CSRF-Token": csrf_token}
        )
        
        # Get new CSRF token
        csrf_response = client.get("/api/auth/csrf-token")
        csrf_token = csrf_response.json()["csrf_token"]
        
        # Try to register again
        response = client.post(
            "/auth/register",
            json={"email": "test@example.com", "password": "AnotherPass456!"},
            headers={"X-CSRF-Token": csrf_token}
        )
        assert response.status_code == 400
        assert "already registered" in response.json()["detail"].lower()
    
    def test_register_invalid_email(self, client):
        """Test that invalid email format is rejected."""
        csrf_response = client.get("/api/auth/csrf-token")
        csrf_token = csrf_response.json()["csrf_token"]
        
        response = client.post(
            "/auth/register",
            json={"email": "not-an-email", "password": "SecurePass123!"},
            headers={"X-CSRF-Token": csrf_token}
        )
        assert response.status_code == 400
        assert "email" in response.json()["detail"].lower()
    
    def test_register_weak_password(self, client):
        """Test that weak passwords are rejected."""
        csrf_response = client.get("/api/auth/csrf-token")
        csrf_token = csrf_response.json()["csrf_token"]
        
        # Test short password
        response = client.post(
            "/auth/register",
            json={"email": "test@example.com", "password": "short"},
            headers={"X-CSRF-Token": csrf_token}
        )
        assert response.status_code == 400
        assert "password" in response.json()["detail"].lower()
    
    def test_register_without_csrf_token(self, client):
        """Test that registration without CSRF token fails."""
        response = client.post(
            "/auth/register",
            json={"email": "test@example.com", "password": "SecurePass123!"}
        )
        assert response.status_code == 403
        assert "csrf" in response.json()["detail"].lower()


@pytest.mark.skip(reason="Login tests require admin-created users in PostgreSQL, not SQLite fixtures")
class TestUserLogin:
    """Test user login functionality."""
    
    @pytest.fixture
    def registered_user(self, client):
        """Create a registered user for testing login."""
        # NOTE: /auth/register endpoint removed - admin creates users
        csrf_response = client.get("/api/auth/csrf-token")
        csrf_token = csrf_response.json()["csrf_token"]
        
        client.post(
            "/auth/register",
            json={"email": "login@example.com", "password": "SecurePass123!"},
            headers={"X-CSRF-Token": csrf_token}
        )
        return {"email": "login@example.com", "password": "SecurePass123!"}
    
    def test_login_success(self, client, registered_user):
        """Test successful login."""
        csrf_response = client.get("/api/auth/csrf-token")
        csrf_token = csrf_response.json()["csrf_token"]
        
        response = client.post(
            "/api/auth/login",
            json=registered_user,
            headers={"X-CSRF-Token": csrf_token}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Login successful"
        
        # Check that session cookie is set
        assert "session_token" in response.cookies
    
    def test_login_invalid_credentials(self, client, registered_user):
        """Test login with incorrect password."""
        csrf_response = client.get("/api/auth/csrf-token")
        csrf_token = csrf_response.json()["csrf_token"]
        
        response = client.post(
            "/api/auth/login",
            json={"email": registered_user["email"], "password": "WrongPassword123!"},
            headers={"X-CSRF-Token": csrf_token}
        )
        assert response.status_code == 401
        assert "invalid" in response.json()["detail"].lower()
    
    def test_login_nonexistent_user(self, client):
        """Test login with non-existent email."""
        csrf_response = client.get("/api/auth/csrf-token")
        csrf_token = csrf_response.json()["csrf_token"]
        
        response = client.post(
            "/api/auth/login",
            json={"email": "nonexistent@example.com", "password": "SecurePass123!"},
            headers={"X-CSRF-Token": csrf_token}
        )
        assert response.status_code == 401
        assert "invalid" in response.json()["detail"].lower()
    
    def test_login_without_csrf_token(self, client, registered_user):
        """Test that login without CSRF token fails."""
        response = client.post("/api/auth/login", json=registered_user)
        assert response.status_code == 403
        assert "csrf" in response.json()["detail"].lower()
    
    def test_login_rate_limiting(self, client, registered_user):
        """Test that rate limiting works for failed login attempts."""
        csrf_response = client.get("/api/auth/csrf-token")
        csrf_token = csrf_response.json()["csrf_token"]
        
        # Make multiple failed login attempts
        for _ in range(11):  # Exceed rate limit (10 attempts/min)
            csrf_response = client.get("/api/auth/csrf-token")
            csrf_token = csrf_response.json()["csrf_token"]
            
            client.post(
                "/api/auth/login",
                json={"email": registered_user["email"], "password": "WrongPassword"},
                headers={"X-CSRF-Token": csrf_token}
            )
        
        # Next attempt should be rate limited
        csrf_response = client.get("/api/auth/csrf-token")
        csrf_token = csrf_response.json()["csrf_token"]
        
        response = client.post(
            "/api/auth/login",
            json={"email": registered_user["email"], "password": "WrongPassword"},
            headers={"X-CSRF-Token": csrf_token}
        )
        assert response.status_code == 429  # Too Many Requests


@pytest.mark.skip(reason="Logout tests require admin-created users in PostgreSQL")
class TestLogout:
    """Test logout functionality."""
    
    @pytest.fixture
    def logged_in_user(self, client):
        """Create and login a user for testing logout."""
        # Register
        csrf_response = client.get("/api/auth/csrf-token")
        csrf_token = csrf_response.json()["csrf_token"]
        
        client.post(
            "/auth/register",
            json={"email": "logout@example.com", "password": "SecurePass123!"},
            headers={"X-CSRF-Token": csrf_token}
        )
        
        # Login
        csrf_response = client.get("/api/auth/csrf-token")
        csrf_token = csrf_response.json()["csrf_token"]
        
        response = client.post(
            "/api/auth/login",
            json={"email": "logout@example.com", "password": "SecurePass123!"},
            headers={"X-CSRF-Token": csrf_token}
        )
        return response.cookies
    
    def test_logout_success(self, client, logged_in_user):
        """Test successful logout."""
        response = client.post("/api/auth/logout", cookies=logged_in_user)
        assert response.status_code == 200
        data = response.json()
        assert "logged out" in data["message"].lower()
    
    def test_logout_without_session(self, client):
        """Test logout without active session."""
        response = client.post("/api/auth/logout")
        assert response.status_code == 200
        # Should succeed even without session


@pytest.mark.skip(reason="Session tests require admin-created users in PostgreSQL")
class TestSessionManagement:
    """Test session management."""
    
    def test_protected_endpoint_without_session(self, client):
        """Test that protected endpoints require authentication."""
        response = client.get("/documents")
        assert response.status_code == 401
    
    def test_protected_endpoint_with_session(self, client):
        """Test that protected endpoints work with valid session."""
        # Register and login
        csrf_response = client.get("/api/auth/csrf-token")
        csrf_token = csrf_response.json()["csrf_token"]
        
        client.post(
            "/auth/register",
            json={"email": "session@example.com", "password": "SecurePass123!"},
            headers={"X-CSRF-Token": csrf_token}
        )
        
        csrf_response = client.get("/api/auth/csrf-token")
        csrf_token = csrf_response.json()["csrf_token"]
        
        login_response = client.post(
            "/api/auth/login",
            json={"email": "session@example.com", "password": "SecurePass123!"},
            headers={"X-CSRF-Token": csrf_token}
        )
        
        # Access protected endpoint
        response = client.get("/documents", cookies=login_response.cookies)
        assert response.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
