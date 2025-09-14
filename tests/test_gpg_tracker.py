#!/usr/bin/env python3
"""
Test script for GPG Key Tracker
"""

import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from gpg_manager import GPGManager
from models import create_database, get_session, GPGKey, UsageLog

class TestGPGTracker(unittest.TestCase):
    """Test cases for GPG Key Tracker"""
    
    def setUp(self):
        """Set up test environment"""
        # Use temporary database for testing
        self.test_db_path = tempfile.mktemp(suffix='.db')
        os.environ['DATABASE_PATH'] = self.test_db_path
        
        # Create test database
        create_database()
        
        # Create GPG manager instance
        self.gpg_manager = GPGManager()
    
    def tearDown(self):
        """Clean up test environment"""
        # Remove test database
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
    
    def test_database_creation(self):
        """Test database creation"""
        session = get_session()
        try:
            # Check if tables exist
            keys = session.query(GPGKey).all()
            logs = session.query(UsageLog).all()
            self.assertIsNotNone(keys)
            self.assertIsNotNone(logs)
        finally:
            session.close()
    
    @patch('gnupg.GPG')
    def test_add_key(self, mock_gpg):
        """Test adding a key"""
        # Mock GPG import result
        mock_import_result = MagicMock()
        mock_import_result.imported = 1
        mock_import_result.fingerprints = ['ABCD1234EFGH5678IJKL9012MNOP3456QRST7890']
        
        # Mock GPG key data
        mock_key_data = {
            'fingerprint': 'ABCD1234EFGH5678IJKL9012MNOP3456QRST7890',
            'keyid': 'ABCD1234EFGH5678',
            'uids': ['Test User <test@example.com>']
        }
        
        mock_gpg.return_value.import_keys.return_value = mock_import_result
        mock_gpg.return_value.list_keys.return_value = [mock_key_data]
        
        # Create temporary key file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.asc', delete=False) as f:
            f.write("-----BEGIN PGP PUBLIC KEY BLOCK-----\n")
            f.write("Test key content\n")
            f.write("-----END PGP PUBLIC KEY BLOCK-----\n")
            key_file = f.name
        
        try:
            # Test adding key
            success = self.gpg_manager.add_key(
                key_file=key_file,
                owner="Test Owner",
                requester="Test Requester",
                jira_ticket="TEST-123"
            )
            
            self.assertTrue(success)
            
            # Verify key was added to database
            keys = self.gpg_manager.list_keys()
            self.assertEqual(len(keys), 1)
            self.assertEqual(keys[0]['owner'], "Test Owner")
            self.assertEqual(keys[0]['requester'], "Test Requester")
            self.assertEqual(keys[0]['jira_ticket'], "TEST-123")
            
        finally:
            # Clean up
            os.unlink(key_file)
    
    def test_log_usage(self):
        """Test usage logging"""
        # Log a test usage
        self.gpg_manager.log_usage(
            fingerprint="ABCD1234EFGH5678IJKL9012MNOP3456QRST7890",
            operation="encrypt",
            user="testuser",
            file_path="/tmp/test.txt",
            recipient="test@example.com"
        )
        
        # Verify log was created
        logs = self.gpg_manager.get_usage_logs()
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]['operation'], "encrypt")
        self.assertEqual(logs[0]['user'], "testuser")
        self.assertEqual(logs[0]['file_path'], "/tmp/test.txt")
        self.assertEqual(logs[0]['recipient'], "test@example.com")
        self.assertTrue(logs[0]['success'])
    
    def test_edit_key(self):
        """Test editing key metadata"""
        # First add a key
        with patch('gnupg.GPG') as mock_gpg:
            mock_import_result = MagicMock()
            mock_import_result.imported = 1
            mock_import_result.fingerprints = ['ABCD1234EFGH5678IJKL9012MNOP3456QRST7890']
            
            mock_key_data = {
                'fingerprint': 'ABCD1234EFGH5678IJKL9012MNOP3456QRST7890',
                'keyid': 'ABCD1234EFGH5678',
                'uids': ['Test User <test@example.com>']
            }
            
            mock_gpg.return_value.import_keys.return_value = mock_import_result
            mock_gpg.return_value.list_keys.return_value = [mock_key_data]
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.asc', delete=False) as f:
                f.write("-----BEGIN PGP PUBLIC KEY BLOCK-----\n")
                f.write("Test key content\n")
                f.write("-----END PGP PUBLIC KEY BLOCK-----\n")
                key_file = f.name
            
            try:
                self.gpg_manager.add_key(
                    key_file=key_file,
                    owner="Original Owner",
                    requester="Original Requester"
                )
                
                # Edit the key
                success = self.gpg_manager.edit_key(
                    fingerprint="ABCD1234EFGH5678IJKL9012MNOP3456QRST7890",
                    owner="New Owner",
                    jira_ticket="NEW-456"
                )
                
                self.assertTrue(success)
                
                # Verify changes
                key_info = self.gpg_manager.get_key_by_fingerprint("ABCD1234EFGH5678IJKL9012MNOP3456QRST7890")
                self.assertEqual(key_info['owner'], "New Owner")
                self.assertEqual(key_info['jira_ticket'], "NEW-456")
                self.assertEqual(key_info['requester'], "Original Requester")  # Should be unchanged
                
            finally:
                os.unlink(key_file)

def run_tests():
    """Run all tests"""
    print("Running GPG Key Tracker tests...")
    unittest.main(verbosity=2)

if __name__ == '__main__':
    run_tests()
