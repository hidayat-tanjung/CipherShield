#!/usr/bin/env python3
"""
CipherShield Decryption Tool 
"""
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import argparse
import getpass  # Import yang diperlukan
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
    print(colored("\nSecure Password Encryption Tool", 'yellow'))
    print(colored("⚡ By: IZUMY\n", 'magenta'))

def decrypt_file(encrypted_file: str, key_file: str, output_file: str) -> bool:
    try:
        # Baca file terenkripsi
        with open(encrypted_file, 'rb') as f:
            data = f.read()
        
        salt = data[:16]
        encrypted_data = data[16:]

        # Input passphrase (tersembunyi)
        passphrase = getpass.getpass(colored("Masukkan passphrase: ", 'blue'))

        # Generate key
        with open(key_file, 'rb') as f:
            stored_key = f.read()
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        derived_key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))

        if derived_key != stored_key:
            print(colored("❌ Passphrase salah atau kunci tidak cocok!", 'red'))
            return False

        fernet = Fernet(derived_key)
        decrypted_data = fernet.decrypt(encrypted_data)

        with open(output_file, 'wb') as f:
            f.write(decrypted_data)

        return True

    except Exception as e:
        print(colored(f"❌ Error: {str(e)}", 'red'))
        return False

def main():
    parser = argparse.ArgumentParser(description='SPET Decryption Tool')
    parser.add_argument('-i', '--input', required=True, help='File terenkripsi')
    parser.add_argument('-k', '--key', required=True, help='File kunci')
    parser.add_argument('-o', '--output', required=True, help='Output file')
    args = parser.parse_args()

    print(colored("\n🔓 SPET Decryption Tool", 'cyan'))
    if decrypt_file(args.input, args.key, args.output):
        print(colored(f"\n✅ Dekripsi berhasil! File disimpan sebagai: {args.output}", 'green'))
        print(colored("💡 Tips: Hapus file terenkripsi setelah digunakan!", 'yellow'))
    else:
        print(colored("\n❌ Gagal mendekripsi", 'red'))

if __name__ == "__main__":
    main()
