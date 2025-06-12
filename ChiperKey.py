#!/usr/bin/env python3
"""
CipherShield - Secure File Encryption/Decryption Tool
"""
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import argparse
import getpass
from termcolor import colored

def display_banner():
    """Display the ASCII art banner"""
    banner = r"""
   _____ _       _               _____ _     _      _     _                    
  / ____(_)     | |             / ____| |   (_)    | |   | |                   
 | |     _ _ __ | |__   ___ _ _| (___ | |__  _  ___| | __| |                   
 | |    | | '_ \| '_ \ / _ \ '__\___ \| '_ \| |/ _ \ |/ _` |                   
 | |____| | |_) | | | |  __/ |  ____) | | | | |  __/ | (_| |                   
  \_____|_| .__/|_| |_|\___|_| |_____/|_| |_|_|\___|_|\__,_|                   
          | |                                                                  
          |_|"""
    print(colored(banner, 'cyan'))
    print(colored("\n⚡ CipherShield - Secure File Encryption/Decryption Tool", 'yellow'))
    print(colored("🔐 By: IZUMY\n", 'magenta'))

def generate_key(passphrase: str, salt: bytes) -> bytes:
    """Generate encryption key from passphrase"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))

def encrypt_file(input_file: str, output_file: str, key_file: str) -> bool:
    """Encrypt a file using Fernet symmetric encryption"""
    try:
        salt = os.urandom(16)
        passphrase = getpass.getpass(colored("Enter encryption passphrase (min 12 chars): ", 'blue'))
        confirm_pass = getpass.getpass(colored("Confirm passphrase: ", 'blue'))
        
        if passphrase != confirm_pass:
            print(colored("❌ Passphrases don't match!", 'red'))
            return False
            
        if len(passphrase) < 12:
            print(colored("❌ Passphrase must be at least 12 characters!", 'red'))
            return False

        key = generate_key(passphrase, salt)
        
        with open(input_file, 'rb') as f:
            data = f.read()
            
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(data)
        
        with open(output_file, 'wb') as f:
            f.write(salt + encrypted_data)
            
        with open(key_file, 'wb') as f:
            f.write(key)
            
        return True
        
    except Exception as e:
        print(colored(f"❌ Encryption failed: {str(e)}", 'red'))
        return False

def decrypt_file(encrypted_file: str, key_file: str, output_file: str) -> bool:
    """Decrypt a file using Fernet symmetric encryption"""
    try:
        with open(encrypted_file, 'rb') as f:
            data = f.read()
        
        salt = data[:16]
        encrypted_data = data[16:]
        
        passphrase = getpass.getpass(colored("Enter decryption passphrase: ", 'blue'))
        stored_key = open(key_file, 'rb').read()
        
        derived_key = generate_key(passphrase, salt)
        
        if derived_key != stored_key:
            print(colored("❌ Wrong passphrase or key mismatch!", 'red'))
            return False
            
        fernet = Fernet(derived_key)
        decrypted_data = fernet.decrypt(encrypted_data)
        
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)
            
        return True
        
    except Exception as e:
        print(colored(f"❌ Decryption failed: {str(e)}", 'red'))
        return False

def main():
    display_banner()
    
    parser = argparse.ArgumentParser(description='CipherShield - File Encryption Tool')
    subparsers = parser.add_subparsers(dest='command', required=True)
    
    # Encryption command
    enc_parser = subparsers.add_parser('encrypt', help='Encrypt a file')
    enc_parser.add_argument('-i', '--input', required=True, help='Input file to encrypt')
    enc_parser.add_argument('-o', '--output', required=True, help='Output encrypted file')
    enc_parser.add_argument('-k', '--key', required=True, help='Key file to save')
    
    # Decryption command
    dec_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
    dec_parser.add_argument('-i', '--input', required=True, help='Encrypted input file')
    dec_parser.add_argument('-o', '--output', required=True, help='Decrypted output file')
    dec_parser.add_argument('-k', '--key', required=True, help='Key file to use')
    
    args = parser.parse_args()
    
    if args.command == 'encrypt':
        print(colored("\n🔒 Encryption Mode", 'green'))
        if encrypt_file(args.input, args.output, args.key):
            print(colored(f"\n✅ Encryption successful! Encrypted file: {args.output}", 'green'))
            print(colored(f"🔑 Key saved to: {args.key}", 'yellow'))
            print(colored("💡 Remember your passphrase - it cannot be recovered!", 'red'))
    else:
        print(colored("\n🔓 Decryption Mode", 'blue'))
        if decrypt_file(args.input, args.key, args.output):
            print(colored(f"\n✅ Decryption successful! File saved to: {args.output}", 'green'))
        else:
            print(colored("\n❌ Decryption failed", 'red'))

if __name__ == "__main__":
    main()
