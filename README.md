## ChipherShield
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

[![GitHub](https://img.shields.io/badge/GitHub-View_Project-blue?logo=github)](https://github.com/hidayat-tanjung/CipherShield)

 
