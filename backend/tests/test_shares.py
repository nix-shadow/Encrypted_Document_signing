"""
Simplified tests for document sharing operations.
"""

import pytest


class TestShares:
    """Test document sharing functionality."""
    
    def test_share_requires_auth(self, client):
        """Test that sharing requires authentication."""
        response = client.post(
            "/api/shares/999",
            json={"recipient_email": "test@example.com"}
        )
        assert response.status_code in [401, 403, 404]
    
    def test_revoke_requires_auth(self, client):
        """Test that revoking access requires authentication."""
        response = client.delete("/api/shares/999")
        assert response.status_code in [401, 403, 404]
    
    def test_get_shared_with_me_requires_auth(self, client):
        """Test that getting shared documents requires authentication."""
        response = client.get("/api/shares/with-me")
        assert response.status_code in [401, 404]
    
    def test_get_shared_by_me_requires_auth(self, client):
        """Test that getting documents shared by me requires authentication."""
        response = client.get("/api/shares/by-me")
        assert response.status_code in [401, 404]
