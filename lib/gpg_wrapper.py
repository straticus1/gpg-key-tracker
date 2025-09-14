#!/usr/bin/env python3
"""
GPG Wrapper - Logs all GPG operations for audit purposes
"""

import gnupg
import os
import sys
import logging
import getpass
from typing import Optional, Dict, Any
from datetime import datetime
from gpg_manager import GPGManager
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GPGWrapper:
    """Wrapper around GPG operations that logs all usage"""
    
    def __init__(self, gpg_home: Optional[str] = None):
        """Initialize GPG wrapper"""
        self.gpg_manager = GPGManager(gpg_home)
        self.gpg = self.gpg_manager.gpg
        self.current_user = getpass.getuser()
    
    def encrypt(self, file_path: str, recipient: str, output_file: Optional[str] = None) -> bool:
        """Encrypt a file and log the operation"""
        try:
            # Determine which key to use for the recipient
            keys = self.gpg_manager.list_keys()
            target_key = None
            
            for key in keys:
                if (key['email'] == recipient or 
                    key['user_id'].lower().find(recipient.lower()) != -1):
                    target_key = key
                    break
            
            if not target_key:
                logger.error(f"No key found for recipient: {recipient}")
                return False
            
            # Perform encryption
            with open(file_path, 'rb') as f:
                encrypted_data = self.gpg.encrypt_file(
                    f, 
                    recipients=[target_key['fingerprint']],
                    output=output_file or f"{file_path}.gpg"
                )
            
            if encrypted_data.ok:
                # Log successful encryption
                self.gpg_manager.log_usage(
                    fingerprint=target_key['fingerprint'],
                    operation='encrypt',
                    user=self.current_user,
                    file_path=file_path,
                    recipient=recipient,
                    success=True
                )
                logger.info(f"Successfully encrypted {file_path} for {recipient}")
                return True
            else:
                # Log failed encryption
                self.gpg_manager.log_usage(
                    fingerprint=target_key['fingerprint'],
                    operation='encrypt',
                    user=self.current_user,
                    file_path=file_path,
                    recipient=recipient,
                    success=False,
                    error_message=str(encrypted_data.status)
                )
                logger.error(f"Encryption failed: {encrypted_data.status}")
                return False
                
        except Exception as e:
            logger.error(f"Error during encryption: {e}")
            return False
    
    def decrypt(self, file_path: str, output_file: Optional[str] = None) -> bool:
        """Decrypt a file and log the operation"""
        try:
            # Perform decryption
            with open(file_path, 'rb') as f:
                decrypted_data = self.gpg.decrypt_file(
                    f,
                    output=output_file or file_path.replace('.gpg', '.decrypted')
                )
            
            if decrypted_data.ok:
                # Find the key used for decryption
                # Note: This is a simplified approach - in practice, you might need
                # to parse the encrypted file to determine which key was used
                keys = self.gpg_manager.list_keys()
                
                # Log successful decryption (using first available key as approximation)
                if keys:
                    self.gpg_manager.log_usage(
                        fingerprint=keys[0]['fingerprint'],
                        operation='decrypt',
                        user=self.current_user,
                        file_path=file_path,
                        success=True
                    )
                
                logger.info(f"Successfully decrypted {file_path}")
                return True
            else:
                # Log failed decryption
                if keys:
                    self.gpg_manager.log_usage(
                        fingerprint=keys[0]['fingerprint'],
                        operation='decrypt',
                        user=self.current_user,
                        file_path=file_path,
                        success=False,
                        error_message=str(decrypted_data.status)
                    )
                
                logger.error(f"Decryption failed: {decrypted_data.status}")
                return False
                
        except Exception as e:
            logger.error(f"Error during decryption: {e}")
            return False
    
    def sign(self, file_path: str, output_file: Optional[str] = None) -> bool:
        """Sign a file and log the operation"""
        try:
            # Get the default signing key
            keys = self.gpg_manager.list_keys()
            if not keys:
                logger.error("No keys available for signing")
                return False
            
            signing_key = keys[0]  # Use first available key
            
            # Perform signing
            with open(file_path, 'rb') as f:
                signed_data = self.gpg.sign_file(
                    f,
                    output=output_file or f"{file_path}.sig",
                    keyid=signing_key['fingerprint']
                )
            
            if signed_data:
                # Log successful signing
                self.gpg_manager.log_usage(
                    fingerprint=signing_key['fingerprint'],
                    operation='sign',
                    user=self.current_user,
                    file_path=file_path,
                    success=True
                )
                logger.info(f"Successfully signed {file_path}")
                return True
            else:
                # Log failed signing
                self.gpg_manager.log_usage(
                    fingerprint=signing_key['fingerprint'],
                    operation='sign',
                    user=self.current_user,
                    file_path=file_path,
                    success=False,
                    error_message="Signing failed"
                )
                logger.error("Signing failed")
                return False
                
        except Exception as e:
            logger.error(f"Error during signing: {e}")
            return False
    
    def verify(self, file_path: str, signature_file: Optional[str] = None) -> bool:
        """Verify a file signature and log the operation"""
        try:
            # Perform verification
            with open(file_path, 'rb') as f:
                if signature_file:
                    with open(signature_file, 'rb') as sig_f:
                        verified = self.gpg.verify_file(sig_f, file_path)
                else:
                    verified = self.gpg.verify_file(f)
            
            if verified:
                # Log successful verification
                keys = self.gpg_manager.list_keys()
                if keys:
                    self.gpg_manager.log_usage(
                        fingerprint=keys[0]['fingerprint'],
                        operation='verify',
                        user=self.current_user,
                        file_path=file_path,
                        success=True
                    )
                
                logger.info(f"Successfully verified {file_path}")
                return True
            else:
                # Log failed verification
                keys = self.gpg_manager.list_keys()
                if keys:
                    self.gpg_manager.log_usage(
                        fingerprint=keys[0]['fingerprint'],
                        operation='verify',
                        user=self.current_user,
                        file_path=file_path,
                        success=False,
                        error_message="Verification failed"
                    )
                
                logger.error("Verification failed")
                return False
                
        except Exception as e:
            logger.error(f"Error during verification: {e}")
            return False

def main():
    """Command-line interface for GPG wrapper"""
    import argparse
    
    parser = argparse.ArgumentParser(description='GPG Wrapper - Logs all GPG operations')
    parser.add_argument('operation', choices=['encrypt', 'decrypt', 'sign', 'verify'],
                       help='GPG operation to perform')
    parser.add_argument('--file', '-f', required=True, help='File to process')
    parser.add_argument('--recipient', '-r', help='Recipient for encryption')
    parser.add_argument('--output', '-o', help='Output file')
    parser.add_argument('--signature', '-s', help='Signature file for verification')
    
    args = parser.parse_args()
    
    wrapper = GPGWrapper()
    
    if args.operation == 'encrypt':
        if not args.recipient:
            print("Error: Recipient is required for encryption")
            sys.exit(1)
        success = wrapper.encrypt(args.file, args.recipient, args.output)
    elif args.operation == 'decrypt':
        success = wrapper.decrypt(args.file, args.output)
    elif args.operation == 'sign':
        success = wrapper.sign(args.file, args.output)
    elif args.operation == 'verify':
        success = wrapper.verify(args.file, args.signature)
    
    if success:
        print(f"{args.operation.capitalize()} operation completed successfully")
        sys.exit(0)
    else:
        print(f"{args.operation.capitalize()} operation failed")
        sys.exit(1)

if __name__ == '__main__':
    main()
