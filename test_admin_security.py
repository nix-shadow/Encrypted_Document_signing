#!/usr/bin/env python3
"""
Test script for admin-controlled security model.

This script tests all the new endpoints and approval workflows.
Run this after setting up the admin user and starting the application.

Usage:
    python test_admin_security.py
"""

import requests
import json
import time
from typing import Optional

BASE_URL = "http://localhost:3001/api"

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

def print_success(msg):
    print(f"{Colors.GREEN}✓ {msg}{Colors.END}")

def print_error(msg):
    print(f"{Colors.RED}✗ {msg}{Colors.END}")

def print_info(msg):
    print(f"{Colors.BLUE}ℹ {msg}{Colors.END}")

def print_warning(msg):
    print(f"{Colors.YELLOW}⚠ {msg}{Colors.END}")

class TestRunner:
    def __init__(self):
        self.admin_token = None
        self.user_token = None
        self.test_user_email = "testuser@example.com"
        self.csrf_token = None
        
    def get_csrf_token(self):
        """Get CSRF token from server."""
        try:
            resp = requests.get(f"{BASE_URL}/auth/csrf-token")
            if resp.status_code == 200:
                self.csrf_token = resp.json()["csrf_token"]
                print_success("CSRF token obtained")
                return True
        except Exception as e:
            print_error(f"Failed to get CSRF token: {e}")
        return False
    
    def test_admin_login(self, email: str, password: str):
        """Test admin login."""
        print_info(f"Testing admin login for {email}...")
        
        try:
            resp = requests.post(
                f"{BASE_URL}/auth/login",
                json={
                    "email": email,
                    "password": password
                },
                headers={"X-CSRF-Token": self.csrf_token}
            )
            
            if resp.status_code == 200:
                # Get session token from cookies
                self.admin_token = resp.cookies.get("session_token")
                if self.admin_token:
                    print_success("Admin login successful")
                    return True
                else:
                    print_error("No session token in response")
            else:
                print_error(f"Login failed: {resp.status_code} - {resp.text}")
        except Exception as e:
            print_error(f"Admin login failed: {e}")
        
        return False
    
    def test_create_user(self):
        """Test admin creating a new user."""
        print_info("Testing user creation by admin...")
        
        try:
            resp = requests.post(
                f"{BASE_URL}/auth/admin/create-user",
                json={
                    "email": self.test_user_email,
                    "password": "TestPass123!",
                    "role": "user"
                },
                headers={"X-CSRF-Token": self.csrf_token},
                cookies={"session_token": self.admin_token}
            )
            
            if resp.status_code == 201:
                data = resp.json()
                print_success(f"User created: {data['email']} (ID: {data['id']})")
                print_info(f"   Role: {data['role']}")
                print_info(f"   Approved: {data['is_approved']}")
                return True
            else:
                print_error(f"User creation failed: {resp.status_code} - {resp.text}")
        except Exception as e:
            print_error(f"User creation failed: {e}")
        
        return False
    
    def test_user_login_pending(self):
        """Test user login that should create pending request."""
        print_info("Testing user login (should create pending request)...")
        
        try:
            resp = requests.post(
                f"{BASE_URL}/auth/login",
                json={
                    "email": self.test_user_email,
                    "password": "TestPass123!"
                },
                headers={"X-CSRF-Token": self.csrf_token}
            )
            
            if resp.status_code == 202:  # Accepted but pending
                data = resp.json()
                if "error" in data and data["error"] == "login_pending_approval":
                    print_success("Login pending approval (as expected)")
                    print_info(f"   Message: {data['message']}")
                    return True
            
            print_error(f"Unexpected response: {resp.status_code} - {resp.text}")
        except Exception as e:
            print_error(f"User login test failed: {e}")
        
        return False
    
    def test_list_pending_logins(self):
        """Test admin listing pending logins."""
        print_info("Testing admin viewing pending logins...")
        
        try:
            resp = requests.get(
                f"{BASE_URL}/auth/admin/pending-logins",
                cookies={"session_token": self.admin_token}
            )
            
            if resp.status_code == 200:
                pending = resp.json()
                print_success(f"Found {len(pending)} pending login(s)")
                for p in pending:
                    print_info(f"   User: {p['user_email']} from {p['device_name']}")
                return len(pending) > 0
            else:
                print_error(f"Failed to list pending logins: {resp.status_code}")
        except Exception as e:
            print_error(f"Failed to list pending logins: {e}")
        
        return False
    
    def test_approve_login(self, pending_id: int):
        """Test admin approving a login."""
        print_info(f"Testing admin approving login {pending_id}...")
        
        try:
            resp = requests.post(
                f"{BASE_URL}/auth/admin/approve-login/{pending_id}",
                json={"approve": True},
                headers={"X-CSRF-Token": self.csrf_token},
                cookies={"session_token": self.admin_token}
            )
            
            if resp.status_code == 200:
                print_success("Login approved")
                return True
            else:
                print_error(f"Approval failed: {resp.status_code} - {resp.text}")
        except Exception as e:
            print_error(f"Approval failed: {e}")
        
        return False
    
    def test_login_status_poll(self):
        """Test user checking login approval status."""
        print_info("Testing login status polling...")
        
        try:
            resp = requests.get(
                f"{BASE_URL}/auth/login/status",
                params={"email": self.test_user_email}
            )
            
            if resp.status_code == 200:
                data = resp.json()
                print_success(f"Status: {data['status']}")
                print_info(f"   Message: {data['message']}")
                return data['status'] == "approved"
            else:
                print_error(f"Status check failed: {resp.status_code}")
        except Exception as e:
            print_error(f"Status check failed: {e}")
        
        return False
    
    def test_list_pending_devices(self):
        """Test admin listing pending device authorizations."""
        print_info("Testing admin viewing pending devices...")
        
        try:
            resp = requests.get(
                f"{BASE_URL}/auth/admin/pending-devices",
                cookies={"session_token": self.admin_token}
            )
            
            if resp.status_code == 200:
                pending = resp.json()
                print_success(f"Found {len(pending)} pending device(s)")
                for p in pending:
                    print_info(f"   User: {p['user_email']}, Device: {p['device_name']}")
                return True
            else:
                print_error(f"Failed to list pending devices: {resp.status_code}")
        except Exception as e:
            print_error(f"Failed to list pending devices: {e}")
        
        return False
    
    def run_full_test(self, admin_email: str, admin_password: str):
        """Run full test suite."""
        print("\n" + "="*60)
        print("  Admin-Controlled Security Model - Test Suite")
        print("="*60 + "\n")
        
        tests_passed = 0
        tests_total = 0
        
        # Test 1: Get CSRF token
        tests_total += 1
        if self.get_csrf_token():
            tests_passed += 1
        
        # Test 2: Admin login
        tests_total += 1
        if not self.test_admin_login(admin_email, admin_password):
            print_error("\nCannot proceed without admin login!")
            return
        tests_passed += 1
        
        # Test 3: Create user
        tests_total += 1
        if self.test_create_user():
            tests_passed += 1
        
        # Test 4: User login (should be pending)
        tests_total += 1
        if self.test_user_login_pending():
            tests_passed += 1
        
        # Test 5: List pending logins
        tests_total += 1
        if self.test_list_pending_logins():
            tests_passed += 1
        
        # Test 6: Get first pending login and approve it
        try:
            resp = requests.get(
                f"{BASE_URL}/auth/admin/pending-logins",
                cookies={"session_token": self.admin_token}
            )
            if resp.status_code == 200:
                pending = resp.json()
                if pending:
                    pending_id = pending[0]["id"]
                    tests_total += 1
                    if self.test_approve_login(pending_id):
                        tests_passed += 1
        except:
            pass
        
        # Test 7: Check login status
        time.sleep(1)  # Give server time to process
        tests_total += 1
        if self.test_login_status_poll():
            tests_passed += 1
        
        # Test 8: List pending devices
        tests_total += 1
        if self.test_list_pending_devices():
            tests_passed += 1
        
        # Print summary
        print("\n" + "="*60)
        print(f"  Test Results: {tests_passed}/{tests_total} passed")
        print("="*60)
        
        if tests_passed == tests_total:
            print_success("All tests passed! ✨")
        else:
            print_warning(f"{tests_total - tests_passed} test(s) failed")
        
        print()


def main():
    """Main function."""
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python test_admin_security.py <admin_email> <admin_password>")
        print("\nExample:")
        print("  python test_admin_security.py admin@example.com MySecurePass123")
        return 1
    
    admin_email = sys.argv[1]
    admin_password = sys.argv[2]
    
    runner = TestRunner()
    runner.run_full_test(admin_email, admin_password)
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
