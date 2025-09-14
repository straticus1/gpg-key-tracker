#!/usr/bin/env python3
"""
Comprehensive tests for GPG Manager
"""

import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock, mock_open
from datetime import datetime, timedelta
from contextlib import contextmanager
import sqlite3

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from gpg_manager import GPGManager
from models import GPGKey, UsageLog, create_database, get_session
from config import Config


class TestGPGManager(unittest.TestCase):
    """Comprehensive test cases for GPG Manager"""

    def setUp(self):
        """Set up test environment"""
        # Create temporary database
        self.test_db_fd, self.test_db_path = tempfile.mkstemp(suffix='.db')
        os.environ['DATABASE_PATH'] = self.test_db_path

        # Create test database
        create_database()

        # Mock config
        self.test_config = Config()
        self.test_config.gpg.home = tempfile.mkdtemp()
        self.test_config.gpg.max_key_size = 1024 * 1024  # 1MB

        # Create GPG manager instance with test config
        self.gpg_manager = GPGManager(config=self.test_config)

    def tearDown(self):
        """Clean up test environment"""
        os.close(self.test_db_fd)
        if os.path.exists(self.test_db_path):
            os.unlink(self.test_db_path)
        # Clean up test GPG home
        import shutil
        if os.path.exists(self.test_config.gpg.home):
            shutil.rmtree(self.test_config.gpg.home)

    def test_validate_fingerprint(self):
        """Test fingerprint validation"""
        # Valid fingerprints
        valid_40 = "A1B2C3D4E5F6789012345678901234567890ABCD"
        valid_64 = "A1B2C3D4E5F6789012345678901234567890ABCDEF123456789012345678901234"

        self.assertTrue(self.gpg_manager._validate_fingerprint(valid_40))
        self.assertTrue(self.gpg_manager._validate_fingerprint(valid_64))

        # Invalid fingerprints
        self.assertFalse(self.gpg_manager._validate_fingerprint(""))
        self.assertFalse(self.gpg_manager._validate_fingerprint("invalid"))
        self.assertFalse(self.gpg_manager._validate_fingerprint("12345"))
        self.assertFalse(self.gpg_manager._validate_fingerprint(None))

    def test_validate_email(self):
        """Test email validation"""
        # Valid emails
        self.assertTrue(self.gpg_manager._validate_email("test@example.com"))
        self.assertTrue(self.gpg_manager._validate_email("user.name@domain.co.uk"))

        # Invalid emails
        self.assertFalse(self.gpg_manager._validate_email(""))
        self.assertFalse(self.gpg_manager._validate_email("invalid"))
        self.assertFalse(self.gpg_manager._validate_email("test@"))
        self.assertFalse(self.gpg_manager._validate_email("@example.com"))
        self.assertFalse(self.gpg_manager._validate_email(None))

    def test_sanitize_input(self):
        """Test input sanitization"""
        # Test basic sanitization
        self.assertEqual(self.gpg_manager._sanitize_input("normal text"), "normal text")
        self.assertEqual(self.gpg_manager._sanitize_input("text<script>"), "textscript")
        self.assertEqual(self.gpg_manager._sanitize_input("text\"with'quotes"), "textwithquotes")

        # Test length limit
        long_text = "a" * 300
        result = self.gpg_manager._sanitize_input(long_text, max_length=100)
        self.assertEqual(len(result), 100)

        # Test empty/None input
        self.assertEqual(self.gpg_manager._sanitize_input(""), "")
        self.assertEqual(self.gpg_manager._sanitize_input(None), "")

    @patch('gnupg.GPG')
    def test_add_key_success(self, mock_gpg):
        """Test successful key addition"""
        # Setup mock
        mock_import_result = MagicMock()
        mock_import_result.imported = 1
        mock_import_result.fingerprints = ['ABCD1234EFGH5678IJKL9012MNOP3456QRST7890']

        mock_key_data = {
            'fingerprint': 'ABCD1234EFGH5678IJKL9012MNOP3456QRST7890',
            'keyid': 'ABCD1234EFGH5678',
            'uids': ['Test User <test@example.com>'],
            'expires': '1735689600'  # Future timestamp
        }

        mock_gpg_instance = mock_gpg.return_value
        mock_gpg_instance.import_keys.return_value = mock_import_result
        mock_gpg_instance.list_keys.return_value = [mock_key_data]

        # Create test key file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.asc', delete=False) as f:
            f.write("-----BEGIN PGP PUBLIC KEY BLOCK-----\n")
            f.write("Test key content\n")
            f.write("-----END PGP PUBLIC KEY BLOCK-----\n")
            key_file = f.name

        try:
            # Test adding key
            result = self.gpg_manager.add_key(
                key_file=key_file,
                owner="Test Owner",
                requester="Test Requester",
                jira_ticket="TEST-123",
                notes="Test notes"
            )

            self.assertTrue(result)

            # Verify key was added to database
            with self.gpg_manager._get_db_session() as session:
                key = session.query(GPGKey).filter_by(
                    fingerprint='ABCD1234EFGH5678IJKL9012MNOP3456QRST7890'
                ).first()

                self.assertIsNotNone(key)
                self.assertEqual(key.owner, "Test Owner")
                self.assertEqual(key.requester, "Test Requester")
                self.assertEqual(key.jira_ticket, "TEST-123")
                self.assertEqual(key.notes, "Test notes")
                self.assertIsNotNone(key.expires_at)

        finally:
            os.unlink(key_file)

    def test_add_key_validation_failures(self):
        """Test key addition validation failures"""
        # Test non-existent file
        result = self.gpg_manager.add_key(
            key_file="/nonexistent/file.asc",
            owner="Test",
            requester="Test"
        )
        self.assertFalse(result)

        # Test empty owner/requester
        with tempfile.NamedTemporaryFile(mode='w', suffix='.asc', delete=False) as f:
            f.write("test content")
            key_file = f.name

        try:
            result = self.gpg_manager.add_key(
                key_file=key_file,
                owner="",
                requester="Test"
            )
            self.assertFalse(result)

            result = self.gpg_manager.add_key(
                key_file=key_file,
                owner="Test",
                requester=""
            )
            self.assertFalse(result)

        finally:
            os.unlink(key_file)

    @patch('gnupg.GPG')
    def test_delete_key(self, mock_gpg):
        """Test key deletion"""
        # First add a key to the database
        fingerprint = 'ABCD1234EFGH5678IJKL9012MNOP3456QRST7890'
        with self.gpg_manager._get_db_session() as session:
            key = GPGKey(
                fingerprint=fingerprint,
                key_id='ABCD1234',
                user_id='Test User <test@example.com>',
                email='test@example.com',
                name='Test User',
                owner='Test Owner',
                requester='Test Requester'
            )
            session.add(key)

        # Setup mock for successful deletion
        mock_gpg_instance = mock_gpg.return_value
        mock_gpg_instance.delete_keys.return_value = True

        # Test deletion
        result = self.gpg_manager.delete_key(fingerprint)
        self.assertTrue(result)

        # Verify key was removed from database
        with self.gpg_manager._get_db_session() as session:
            key = session.query(GPGKey).filter_by(fingerprint=fingerprint).first()
            self.assertIsNone(key)

    def test_edit_key(self):
        """Test key metadata editing"""
        # First add a key to the database
        fingerprint = 'ABCD1234EFGH5678IJKL9012MNOP3456QRST7890'
        with self.gpg_manager._get_db_session() as session:
            key = GPGKey(
                fingerprint=fingerprint,
                key_id='ABCD1234',
                user_id='Test User <test@example.com>',
                owner='Original Owner',
                requester='Original Requester'
            )
            session.add(key)

        # Test editing
        result = self.gpg_manager.edit_key(
            fingerprint=fingerprint,
            owner="New Owner",
            jira_ticket="NEW-456"
        )
        self.assertTrue(result)

        # Verify changes
        with self.gpg_manager._get_db_session() as session:
            key = session.query(GPGKey).filter_by(fingerprint=fingerprint).first()
            self.assertEqual(key.owner, "New Owner")
            self.assertEqual(key.jira_ticket, "NEW-456")
            self.assertEqual(key.requester, "Original Requester")  # Should be unchanged

    def test_log_usage(self):
        """Test usage logging"""
        fingerprint = 'ABCD1234EFGH5678IJKL9012MNOP3456QRST7890'

        # Add a key first
        with self.gpg_manager._get_db_session() as session:
            key = GPGKey(
                fingerprint=fingerprint,
                key_id='ABCD1234',
                user_id='Test User',
                owner='Test Owner',
                requester='Test Requester',
                usage_count=5
            )
            session.add(key)

        # Test logging
        result = self.gpg_manager.log_usage(
            fingerprint=fingerprint,
            operation="encrypt",
            user="testuser",
            file_path="/tmp/test.txt",
            recipient="test@example.com",
            success=True
        )
        self.assertTrue(result)

        # Verify log was created and key stats updated
        with self.gpg_manager._get_db_session() as session:
            log = session.query(UsageLog).filter_by(fingerprint=fingerprint).first()
            self.assertIsNotNone(log)
            self.assertEqual(log.operation, "encrypt")
            self.assertEqual(log.user, "testuser")
            self.assertTrue(log.success)

            # Check key usage stats were updated
            key = session.query(GPGKey).filter_by(fingerprint=fingerprint).first()
            self.assertEqual(key.usage_count, 6)  # Should be incremented
            self.assertIsNotNone(key.last_used_at)

    def test_get_expiring_keys(self):
        """Test getting expiring keys"""
        # Add keys with different expiry dates
        with self.gpg_manager._get_db_session() as session:
            # Key expiring in 10 days
            key1 = GPGKey(
                fingerprint='1111111111111111111111111111111111111111',
                key_id='11111111',
                user_id='User 1',
                owner='Owner 1',
                requester='Requester 1',
                expires_at=datetime.utcnow() + timedelta(days=10),
                is_active=True
            )

            # Key expiring in 60 days (outside default 30-day window)
            key2 = GPGKey(
                fingerprint='2222222222222222222222222222222222222222',
                key_id='22222222',
                user_id='User 2',
                owner='Owner 2',
                requester='Requester 2',
                expires_at=datetime.utcnow() + timedelta(days=60),
                is_active=True
            )

            # Already expired key
            key3 = GPGKey(
                fingerprint='3333333333333333333333333333333333333333',
                key_id='33333333',
                user_id='User 3',
                owner='Owner 3',
                requester='Requester 3',
                expires_at=datetime.utcnow() - timedelta(days=5),
                is_active=True
            )

            session.add_all([key1, key2, key3])

        # Test getting expiring keys (default 30 days)
        expiring_keys = self.gpg_manager.get_expiring_keys()
        self.assertEqual(len(expiring_keys), 1)  # Only key1 should be returned
        self.assertEqual(expiring_keys[0]['fingerprint'], '1111111111111111111111111111111111111111')

        # Test with larger window
        expiring_keys = self.gpg_manager.get_expiring_keys(days_ahead=90)
        self.assertEqual(len(expiring_keys), 2)  # key1 and key2

    def test_get_expired_keys(self):
        """Test getting expired keys"""
        # Add expired key
        with self.gpg_manager._get_db_session() as session:
            expired_key = GPGKey(
                fingerprint='1111111111111111111111111111111111111111',
                key_id='11111111',
                user_id='User 1',
                owner='Owner 1',
                requester='Requester 1',
                expires_at=datetime.utcnow() - timedelta(days=10),
                is_active=True
            )
            session.add(expired_key)

        expired_keys = self.gpg_manager.get_expired_keys()
        self.assertEqual(len(expired_keys), 1)
        self.assertEqual(expired_keys[0]['fingerprint'], '1111111111111111111111111111111111111111')
        self.assertEqual(expired_keys[0]['days_since_expiry'], 10)

    def test_update_key_expiry_status(self):
        """Test updating key expiry status"""
        with self.gpg_manager._get_db_session() as session:
            # Key that should be marked as expired
            key1 = GPGKey(
                fingerprint='1111111111111111111111111111111111111111',
                key_id='11111111',
                user_id='User 1',
                owner='Owner 1',
                requester='Requester 1',
                expires_at=datetime.utcnow() - timedelta(days=5),
                is_expired=False,
                is_active=True
            )

            # Key that should be marked as not expired (was previously expired but renewed)
            key2 = GPGKey(
                fingerprint='2222222222222222222222222222222222222222',
                key_id='22222222',
                user_id='User 2',
                owner='Owner 2',
                requester='Requester 2',
                expires_at=datetime.utcnow() + timedelta(days=30),
                is_expired=True,  # Previously marked as expired
                is_active=True
            )

            session.add_all([key1, key2])

        updated_count = self.gpg_manager.update_key_expiry_status()
        self.assertEqual(updated_count, 2)

        # Verify status was updated
        with self.gpg_manager._get_db_session() as session:
            key1 = session.query(GPGKey).filter_by(
                fingerprint='1111111111111111111111111111111111111111'
            ).first()
            key2 = session.query(GPGKey).filter_by(
                fingerprint='2222222222222222222222222222222222222222'
            ).first()

            self.assertTrue(key1.is_expired)
            self.assertFalse(key2.is_expired)

    def test_list_keys(self):
        """Test listing keys"""
        # Add test keys
        with self.gpg_manager._get_db_session() as session:
            active_key = GPGKey(
                fingerprint='1111111111111111111111111111111111111111',
                key_id='11111111',
                user_id='Active User',
                owner='Owner 1',
                requester='Requester 1',
                is_active=True
            )

            inactive_key = GPGKey(
                fingerprint='2222222222222222222222222222222222222222',
                key_id='22222222',
                user_id='Inactive User',
                owner='Owner 2',
                requester='Requester 2',
                is_active=False
            )

            session.add_all([active_key, inactive_key])

        # Test listing active keys only (default)
        active_keys = self.gpg_manager.list_keys()
        self.assertEqual(len(active_keys), 1)
        self.assertEqual(active_keys[0]['fingerprint'], '1111111111111111111111111111111111111111')

        # Test listing all keys
        all_keys = self.gpg_manager.list_keys(include_inactive=True)
        self.assertEqual(len(all_keys), 2)

    def test_get_usage_logs(self):
        """Test getting usage logs"""
        fingerprint = 'ABCD1234EFGH5678IJKL9012MNOP3456QRST7890'

        # Add test logs
        with self.gpg_manager._get_db_session() as session:
            for i in range(5):
                log = UsageLog(
                    fingerprint=fingerprint,
                    operation="encrypt",
                    user=f"user{i}",
                    success=i % 2 == 0,  # Alternate success/failure
                    timestamp=datetime.utcnow() - timedelta(hours=i)
                )
                session.add(log)

        # Test getting logs with limit
        logs = self.gpg_manager.get_usage_logs(limit=3)
        self.assertEqual(len(logs), 3)

        # Test getting logs for specific fingerprint
        logs = self.gpg_manager.get_usage_logs(fingerprint=fingerprint)
        self.assertEqual(len(logs), 5)

        # Test with invalid fingerprint
        logs = self.gpg_manager.get_usage_logs(fingerprint="invalid")
        self.assertEqual(len(logs), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)