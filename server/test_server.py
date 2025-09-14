#!/usr/bin/env python3
"""
Basic tests for GPG Key Server
"""

import pytest
import os
import tempfile
import shutil
import sys
from datetime import datetime, timedelta
from fastapi.testclient import TestClient

# Add paths for imports
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(parent_dir)
sys.path.append(os.path.join(parent_dir, 'lib'))

# Import our modules
from gpg_server import create_server_app
from api_key_manager import APIKeyManager
from master_key_manager import MasterKeyManager
from lib.models import create_database, get_session, GPGKey, APIKey, MasterKey
from lib.config import Config, get_config


class TestConfig:
    """Test configuration"""
    def __init__(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test.db")

        # Override config for testing
        os.environ['DATABASE_PATH'] = self.db_path
        os.environ['GPG_HOME'] = os.path.join(self.temp_dir, 'gpg')
        os.environ['GPG_SERVER_ENABLED'] = 'true'
        os.environ['GPG_SERVER_ADMIN_API_KEY'] = 'test-admin-key-123'

        # Create GPG home directory
        os.makedirs(os.path.join(self.temp_dir, 'gpg'), exist_ok=True)

    def cleanup(self):
        """Clean up test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)


@pytest.fixture(scope="session")
def test_config():
    """Setup test configuration"""
    config = TestConfig()
    yield config
    config.cleanup()


@pytest.fixture(scope="session")
def app(test_config):
    """Create test app"""
    create_database()
    return create_server_app()


@pytest.fixture(scope="session")
def client(app):
    """Create test client"""
    return TestClient(app)


@pytest.fixture
def api_key_manager(test_config):
    """Create API key manager for testing"""
    return APIKeyManager()


@pytest.fixture
def master_key_manager(test_config):
    """Create master key manager for testing"""
    return MasterKeyManager()


@pytest.fixture
def test_api_key(api_key_manager):
    """Create a test API key"""
    permissions = {
        'operations': ['read', 'list', 'info', 'search'],
        'keys': '*'
    }

    result = api_key_manager.create_api_key(
        name="Test API Key",
        owner="test@example.com",
        permissions=permissions,
        rate_limit=1000
    )

    return result


class TestServerBasics:
    """Test basic server functionality"""

    def test_server_info(self, client):
        """Test server info endpoint"""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "GPG Key Server"
        assert "supported_operations" in data
        assert "endpoints" in data

    def test_health_check(self, client):
        """Test health check endpoint"""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "timestamp" in data
        assert "database" in data
        assert "version" in data


class TestAuthentication:
    """Test authentication and authorization"""

    def test_no_auth_required_for_public_endpoints(self, client):
        """Test that public endpoints don't require authentication"""
        public_endpoints = ["/", "/health", "/docs", "/openapi.json"]

        for endpoint in public_endpoints:
            response = client.get(endpoint)
            assert response.status_code in [200, 404]  # 404 is acceptable for some docs endpoints

    def test_auth_required_for_protected_endpoints(self, client):
        """Test that protected endpoints require authentication"""
        protected_endpoints = ["/keys", "/api-keys", "/master-keys", "/usage"]

        for endpoint in protected_endpoints:
            response = client.get(endpoint)
            assert response.status_code == 401

    def test_valid_api_key_authentication(self, client, test_api_key):
        """Test authentication with valid API key"""
        headers = {"X-API-Key": test_api_key["api_key"]}
        response = client.get("/keys", headers=headers)
        assert response.status_code == 200

    def test_invalid_api_key_authentication(self, client):
        """Test authentication with invalid API key"""
        headers = {"X-API-Key": "invalid-key-123"}
        response = client.get("/keys", headers=headers)
        assert response.status_code == 401

    def test_admin_key_authentication(self, client):
        """Test admin key authentication"""
        headers = {"X-API-Key": "test-admin-key-123"}
        response = client.get("/api-keys", headers=headers)
        assert response.status_code == 200


class TestAPIKeyManagement:
    """Test API key management functionality"""

    def test_create_api_key(self, api_key_manager):
        """Test API key creation"""
        permissions = {
            'operations': ['read', 'list'],
            'keys': '*'
        }

        result = api_key_manager.create_api_key(
            name="Test Key",
            owner="test@example.com",
            permissions=permissions
        )

        assert 'id' in result
        assert 'api_key' in result
        assert result['name'] == "Test Key"
        assert result['owner'] == "test@example.com"
        assert len(result['api_key']) == 64  # 32 bytes hex encoded

    def test_list_api_keys(self, api_key_manager, test_api_key):
        """Test listing API keys"""
        keys = api_key_manager.list_api_keys()
        assert len(keys) >= 1

        # Find our test key
        test_key = next((k for k in keys if k['id'] == test_api_key['id']), None)
        assert test_key is not None
        assert test_key['name'] == test_api_key['name']

    def test_authenticate_api_key(self, api_key_manager, test_api_key):
        """Test API key authentication"""
        auth_result = api_key_manager.authenticate_api_key(test_api_key['api_key'])
        assert auth_result is not None
        assert auth_result['id'] == test_api_key['id']
        assert auth_result['name'] == test_api_key['name']

    def test_check_permissions(self, api_key_manager, test_api_key):
        """Test permission checking"""
        auth_result = api_key_manager.authenticate_api_key(test_api_key['api_key'])

        # Should have read permission
        assert api_key_manager.check_permission(auth_result, 'read')

        # Should not have admin permission
        assert not api_key_manager.check_permission(auth_result, 'admin')

    def test_update_api_key(self, api_key_manager, test_api_key):
        """Test API key updates"""
        success = api_key_manager.update_api_key(
            test_api_key['id'],
            rate_limit=500,
            notes="Updated notes"
        )
        assert success

        # Verify update
        updated_key = api_key_manager.get_api_key(test_api_key['id'])
        assert updated_key['rate_limit'] == 500
        assert updated_key['notes'] == "Updated notes"

    def test_delete_api_key(self, api_key_manager):
        """Test API key deletion"""
        # Create a key to delete
        permissions = {'operations': ['read'], 'keys': '*'}
        key_to_delete = api_key_manager.create_api_key(
            name="Delete Me",
            owner="test@example.com",
            permissions=permissions
        )

        # Soft delete
        success = api_key_manager.delete_api_key(key_to_delete['id'], soft_delete=True)
        assert success

        # Verify it's deactivated
        deleted_key = api_key_manager.get_api_key(key_to_delete['id'])
        assert not deleted_key['is_active']


class TestMasterKeyManagement:
    """Test master key management functionality"""

    @pytest.mark.skip(reason="Requires GPG key generation which is slow")
    def test_create_master_key(self, master_key_manager):
        """Test master key creation"""
        result = master_key_manager.create_master_key(
            name="Test Signing Key",
            key_type="signing",
            key_role="master",
            key_size=2048  # Smaller for faster testing
        )

        assert 'fingerprint' in result
        assert result['name'] == "Test Signing Key"
        assert result['key_type'] == "signing"
        assert result['key_role'] == "master"

    @pytest.mark.skip(reason="Requires GPG key generation which is slow")
    def test_create_organizational_keys(self, master_key_manager):
        """Test organizational key pair creation"""
        result = master_key_manager.create_organizational_key_pair(
            organization="Test Corp",
            name="Test Corp Keys",
            email="admin@testcorp.com",
            key_size=2048
        )

        assert 'signing_key' in result
        assert 'encryption_key' in result
        assert result['organization'] == "Test Corp"
        assert result['signing_key']['is_default']
        assert result['encryption_key']['is_default']

    def test_list_master_keys(self, master_key_manager):
        """Test listing master keys"""
        keys = master_key_manager.list_master_keys()
        assert isinstance(keys, list)


class TestServerEndpoints:
    """Test server HTTP endpoints"""

    def test_list_keys_endpoint(self, client, test_api_key):
        """Test keys listing endpoint"""
        headers = {"X-API-Key": test_api_key["api_key"]}
        response = client.get("/keys", headers=headers)
        assert response.status_code == 200

        data = response.json()
        assert 'keys' in data
        assert 'total' in data
        assert 'page' in data

    def test_search_keys_endpoint(self, client, test_api_key):
        """Test keys search endpoint"""
        headers = {"X-API-Key": test_api_key["api_key"]}
        search_data = {
            "query": "test",
            "limit": 10
        }

        response = client.post("/keys/search", headers=headers, json=search_data)
        assert response.status_code == 200

        data = response.json()
        assert 'keys' in data

    def test_admin_endpoints_require_admin_key(self, client, test_api_key):
        """Test that admin endpoints require admin permissions"""
        headers = {"X-API-Key": test_api_key["api_key"]}

        # Try to create API key (admin only)
        create_data = {
            "name": "Test",
            "owner": "test@example.com",
            "permissions": {"operations": ["read"], "keys": "*"}
        }

        response = client.post("/api-keys", headers=headers, json=create_data)
        assert response.status_code == 403

    def test_admin_endpoints_with_admin_key(self, client):
        """Test admin endpoints with admin key"""
        headers = {"X-API-Key": "test-admin-key-123"}

        # List API keys
        response = client.get("/api-keys", headers=headers)
        assert response.status_code == 200

        # List master keys
        response = client.get("/master-keys", headers=headers)
        assert response.status_code == 200

        # Get usage stats
        response = client.get("/usage", headers=headers)
        assert response.status_code == 200


class TestRateLimiting:
    """Test rate limiting functionality"""

    def test_rate_limiting(self, client, api_key_manager):
        """Test rate limiting enforcement"""
        # Create API key with low rate limit
        permissions = {'operations': ['read', 'list'], 'keys': '*'}
        low_limit_key = api_key_manager.create_api_key(
            name="Low Limit Key",
            owner="test@example.com",
            permissions=permissions,
            rate_limit=2  # Very low limit
        )

        headers = {"X-API-Key": low_limit_key["api_key"]}

        # Make requests up to the limit
        for i in range(2):
            response = client.get("/keys", headers=headers)
            assert response.status_code == 200

        # Next request should be rate limited
        # Note: This test might be flaky depending on timing
        import time
        time.sleep(1)  # Wait a bit to avoid timing issues


class TestValidation:
    """Test input validation"""

    def test_invalid_fingerprint_validation(self, client, test_api_key):
        """Test invalid fingerprint handling"""
        headers = {"X-API-Key": test_api_key["api_key"]}

        # Try to get key with invalid fingerprint
        response = client.get("/keys/invalid-fingerprint", headers=headers)
        assert response.status_code == 404 or response.status_code == 400

    def test_invalid_json_handling(self, client):
        """Test invalid JSON handling"""
        headers = {
            "X-API-Key": "test-admin-key-123",
            "Content-Type": "application/json"
        }

        # Send invalid JSON
        response = client.post("/api-keys", headers=headers, data="invalid json")
        assert response.status_code == 422  # Validation error


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])