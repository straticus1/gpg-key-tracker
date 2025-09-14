#!/usr/bin/env python3
"""
Example usage of GPG Key Tracker
"""

import os
import tempfile
from gpg_manager import GPGManager
from gpg_wrapper import GPGWrapper

def main():
    """Demonstrate GPG tracker functionality"""
    print("GPG Key Tracker - Example Usage")
    print("=" * 40)
    
    # Initialize GPG manager
    gpg_manager = GPGManager()
    
    # Create a sample key file (for demonstration)
    with tempfile.NamedTemporaryFile(mode='w', suffix='.asc', delete=False) as f:
        f.write("-----BEGIN PGP PUBLIC KEY BLOCK-----\n")
        f.write("Version: GnuPG v2.0.22 (GNU/Linux)\n\n")
        f.write("mQENBFxX4XQBCADB...\n")  # Truncated for brevity
        f.write("-----END PGP PUBLIC KEY BLOCK-----\n")
        key_file = f.name
    
    try:
        # Example 1: Add a key
        print("\n1. Adding a GPG key...")
        success = gpg_manager.add_key(
            key_file=key_file,
            owner="John Doe",
            requester="Jane Smith",
            jira_ticket="PROJ-123",
            notes="Production key for API encryption"
        )
        
        if success:
            print("✓ Key added successfully!")
        else:
            print("✗ Failed to add key")
            return
        
        # Example 2: List keys
        print("\n2. Listing all keys...")
        keys = gpg_manager.list_keys()
        for key in keys:
            print(f"  - {key['fingerprint'][:16]}... ({key['owner']})")
        
        # Example 3: Log usage
        print("\n3. Logging key usage...")
        gpg_manager.log_usage(
            fingerprint=keys[0]['fingerprint'],
            operation="encrypt",
            user="testuser",
            file_path="/tmp/document.txt",
            recipient="user@example.com"
        )
        print("✓ Usage logged!")
        
        # Example 4: View logs
        print("\n4. Viewing usage logs...")
        logs = gpg_manager.get_usage_logs(limit=5)
        for log in logs:
            status = "✓" if log['success'] else "✗"
            print(f"  {status} {log['operation']} by {log['user']} at {log['timestamp']}")
        
        # Example 5: Edit key metadata
        print("\n5. Editing key metadata...")
        success = gpg_manager.edit_key(
            keys[0]['fingerprint'],
            owner="Updated Owner",
            jira_ticket="PROJ-456"
        )
        
        if success:
            print("✓ Key metadata updated!")
        else:
            print("✗ Failed to update key metadata")
        
        print("\nExample completed successfully!")
        
    except Exception as e:
        print(f"Error during example: {e}")
    
    finally:
        # Clean up
        if os.path.exists(key_file):
            os.unlink(key_file)

if __name__ == '__main__':
    main()
