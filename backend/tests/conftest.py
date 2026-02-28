"""
Simplified pytest fixtures.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.db import Base, get_db
from app.utils.csrf import csrf_tokens
import warnings

# Suppress passlib deprecation warning
warnings.filterwarnings("ignore", message=".*'crypt' is deprecated.*")

# Test database setup
SQLALCHEMY_TEST_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(
    SQLALCHEMY_TEST_DATABASE_URL, 
    connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function", autouse=True)
def setup_db():
    """Setup and teardown database for each test."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
    csrf_tokens.clear()


@pytest.fixture(scope="function")
def db():
    """Create test database session."""
    session = TestingSessionLocal()
    
    # Override the dependency to use this session
    def override_get_db():
        try:
            yield session
        finally:
            pass
    
    app.dependency_overrides[get_db] = override_get_db
    
    yield session
    
    session.close()
    app.dependency_overrides.clear()


@pytest.fixture(scope="function")
def client(db):
    """Create test client with database."""
    with TestClient(app) as test_client:
        yield test_client
