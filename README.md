## 🔐 ChipherShield
Description:
ChipherShield is a robust Python-based solution for encrypting sensitive password files using Fernet (AES-128) with enhanced security features. The tool provides:

* Strong encryption using PBKDF2 key derivation
* Secure file handling with salt storage
* Passphrase verification
* Colorful terminal interface with ASCII art
* Secure deletion of original files

## Features
* Military-grade encryption: Uses AES-128 via Fernet with 480,000 PBKDF2 iterations
* Passphrase protection: Minimum 12-character passphrase requirement with verification
* Secure key handling: Generates and stores encryption keys separately
* Data integrity: Includes salt in encrypted output for added security
* Clean deletion: Securely overwrites original files before deletion
* User-friendly: Color-coded output and clear instructions
![deepseek_mermaid_20250612_562aad](https://github.com/user-attachments/assets/222d7bb7-84cd-45bc-9790-920b00e328f7)

##  Installation
```console
git colone https://github.com/hidayat-tanjung/CipherShield
cd CipherShield
pip install -r requirements.txt
chmod +x CipherShield.py
```

or manual instal
```console
pip install cryptography pyfiglet termcolor
```

```console
python CipherShield.py -i input.txt -o encrypted.dat -k secret.key
```

Build in Docker:
```console
docker build -t spet .
docker run -v $(pwd):/data spet -i /data/input.txt -o /data/encrypted.dat -k /data/key.key
```

## Example Workflow
1. Create a sample password file:
```console
echo "my_super_secret_password" > passwords.txt
```
2. Encrypt the file:
```console
python spet.py -i passwords.txt -o secure.dat -k mykey.key
```
3. Follow the on-screen prompts to enter and confirm your passphrase.

🔒 Security Considerations
1. Key Management:
   - Store the key file separately from the encrypted data
   - Consider encrypting the key file for additional protection
2. Passphrase Best Practices:
    - Use a minimum of 12 characters
    - Include upper/lower case, numbers, and special characters
    - Never reuse passphrases from other systems
3. File Handling:
    - The tool securely overwrites the original file before deletion
    - Ensure proper file permissions on all generated files

## 🛠️ Testing
```console
# Create test file
echo "test_password" > test.txt

# Encrypt
python spet.py -i test.txt -o test.enc -k test.key

# Verify file was encrypted
file test.enc  # Should show "data"
```
## Building Standalone Executable
You can create a standalone executable using PyInstaller:
```console
pip install pyinstaller
pyinstaller --onefile spet.py
```

## 🔐 ChiperKey - Secure File Encryption Tool
![deepseek_mermaid_20250612_02863e](https://github.com/user-attachments/assets/0b14b311-4ce8-494b-91c4-5052c16ee919)

Description:
A robust Python-based utility for encrypting and decrypting files using AES-256 cryptography with PBKDF2 key derivation. Designed for protecting sensitive data with military-grade encryption.

## Features:
* 256-bit AES encryption (Fernet implementation)
* PBKDF2 key derivation with 480,000 iterations
* Random salt generation for each operation
* Dual-layer protection (key file + passphrase)
* Password confirmation and complexity enforcement

## 🛠️ Usage Guide
Encrypting Files
```console
python ChiperKey.py encrypt -i confidential.docx -o secure.enc -k secret.key
```

Process:

1. You'll be prompted to enter (and confirm) a passphrase (minimum 12 characters)
2. Generates two files:
   - secure.enc (encrypted data + salt)
   - secret.key (derived encryption key)
  
     
Decrypting Files
```console
python ChiperKey.py decrypt -i secure.enc -o document.docx -k secret.key
```
Requirements:
* Original key file used for encryption
* Correct passphrase

⚠️ Critical Security Notes
1. Key File (*.key)
   * Contains the derived encryption key (not your passphrase)
   * Cannot be regenerated without the original passphrase
   * Store separately from encrypted files
2. Passphrase Requirements:
   * Minimum 12 characters
   * Not stored anywhere in the system
   * Example of strong passphrase: C0mpl3x!P@ss2024

Common Errors:
```console
❌ Wrong passphrase or key mismatch!
❌ Passphrases don't match!
❌ Encryption/Decryption failed: [error details]
```

## 🔒 Security Best Practices

```console
gpg -c secret.key  # Encrypt key file with GPG
```

## 📋 Complete Workflow Example

Encrypt a financial report:
```console
python ChiperKey.py encrypt -i Q2_report.xlsx -o Q2_encrypted.enc -k finance2024.key
```

Decrypt when needed:
```console
python ChiperKey.py decrypt -i Q2_encrypted.enc -o Q2_restored.xlsx -k finance2024.key
```

[![GitHub](https://img.shields.io/badge/GitHub-View_Project-blue?logo=github)](https://github.com/hidayat-tanjung/CipherShield)

 
