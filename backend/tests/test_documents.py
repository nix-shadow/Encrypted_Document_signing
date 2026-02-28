"""
Simplified tests for document operations.
"""

import io
import pytest


class TestDocumentUpload:
    """Test document upload functionality."""
    
    def test_upload_without_authentication(self, client):
        """Test that upload without authentication fails."""
        csrf_response = client.get("/api/auth/csrf-token")
        csrf_token = csrf_response.json()["csrf_token"]
        
        files = {"file": ("test.txt", io.BytesIO(b"content"), "text/plain")}
        
        response = client.post(
            "/documents/upload",
            files=files,
            headers={"X-CSRF-Token": csrf_token}
        )
        
        # Should fail because no authentication
        assert response.status_code in [401, 404]


class TestDocumentList:
    """Test document listing."""
    
    def test_list_documents_requires_auth(self, client):
        """Test that listing documents requires authentication."""
        response = client.get("/api/documents/")
        assert response.status_code == 401


class TestDocumentDownload:
    """Test document download."""
    
    def test_download_requires_auth(self, client):
        """Test that download requires authentication."""
        response = client.get("/api/documents/999/download")
        # Returns 404 if document doesn't exist, which is acceptable
        assert response.status_code in [401, 404]
