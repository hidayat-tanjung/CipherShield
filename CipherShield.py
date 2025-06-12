#!/usr/bin/env python3
"""
Secure Password Encryption Tool (SPET)
A robust solution for encrypting sensitive password files using Fernet (AES-128)
with enhanced security features and colorful ASCII art banner.
"""

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import sys
import getpass
import base64
import argparse
from typing import Tuple
from pyfiglet import Figlet
from termcolor import colored

banner = r"""
   _____ _       _               _____ _     _      _     _ 
  / ____(_)     | |             / ____| |   (_)    | |   | |
 | |     _ _ __ | |__   ___ _ _| (___ | |__  _  ___| | __| |
 | |    | | '_ \| '_ \ / _ \ '__\___ \| '_ \| |/ _ \ |/ _` |
 | |____| | |_) | | | |  __/ |  ____) | | | | |  __/ | (_| |
  \_____|_| .__/|_| |_|\___|_| |_____/|_| |_|_|\___|_|\__,_|
          | |                                               
          |_|                                               

                                                                                                                                                                                                              
     [!] By : IZUMY
"""
print(banner)
   

def generate_fernet_key(password: str, salt: bytes) -> bytes:
    """Derive a secure Fernet key from a password using PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(input_file: str, output_file: str, key_file: str) -> Tuple[bool, str]:
    """Encrypt the password file and handle all operations"""
    try:
        # Generate a random salt
        salt = os.urandom(16)
        
        # Get password from user with verification
        while True:
            user_password = getpass.getpass(colored("Enter encryption passphrase (min 12 chars): ", 'blue'))
            if len(user_password) < 12:
                print(colored("❌ Passphrase must be at least 12 characters", 'red'))
                continue
                
            verify_password = getpass.getpass(colored("Confirm encryption passphrase: ", 'blue'))
            if user_password == verify_password:
                break
            print(colored("❌ Passphrases do not match. Try again.", 'red'))
            
        # Generate the Fernet key
        key = generate_fernet_key(user_password, salt)
        fernet = Fernet(key)
        
        # Read and encrypt the password file
        with open(input_file, 'rb') as f:
            original = f.read()
        
        encrypted = fernet.encrypt(original)
        
        # Write the encrypted data and key file
        with open(output_file, 'wb') as f:
            f.write(salt + encrypted)  # Store salt with encrypted data
        
        with open(key_file, 'wb') as f:
            f.write(key)
        
        # Securely delete the original file
        with open(input_file, 'wb') as f:
            f.write(os.urandom(len(original)))
        os.remove(input_file)
        
        return True, "Encryption successful"
    
    except FileNotFoundError:
        return False, f"File not found: {input_file}"
    except PermissionError:
        return False, "Permission denied"
    except Exception as e:
        return False, f"Error: {str(e)}"

def main():
    parser = argparse.ArgumentParser(
        epilog=colored("Example: python spet.py -i passwords.txt -o encrypted.dat -k secret.key", 'cyan'),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-i', '--input', required=True, help="Input password file")
    parser.add_argument('-o', '--output', required=True, help="Output encrypted file")
    parser.add_argument('-k', '--key', required=True, help="Output key file")
    
    args = parser.parse_args()
    
    # Display colorful banner
    display_banner()
    
    if not os.path.exists(args.input):
        print(colored(f"❌ Error: Input file '{args.input}' not found", 'red'))
        sys.exit(1)
        
    success, message = encrypt_file(args.input, args.output, args.key)
    
    if success:
        print(colored("\n✅ " + message, 'green'))
        print(colored(f"🔑 Key saved to: {args.key}", 'blue'))
        print(colored(f"🔒 Encrypted data saved to: {args.output}", 'blue'))
        print(colored("\n⚠️  IMPORTANT SECURITY NOTES:", 'yellow', attrs=['bold']))
        print(colored("1. Store the key file separately from the encrypted data", 'yellow'))
        print(colored("2. Never share your passphrase or key file", 'yellow'))
        print(colored("3. Keep backups of both the key and encrypted file", 'yellow'))
    else:
        print(colored("\n❌ " + message, 'red'), file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    # Check for required dependencies
    try:
        from pyfiglet import Figlet
        from termcolor import colored
    except ImportError:
        print("Required packages not found. Please install with:")
        print("pip install pyfiglet termcolor")
        sys.exit(1)
    
    main()
