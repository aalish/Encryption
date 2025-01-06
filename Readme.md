# File and Folder Encryption/Decryption Script

## Overview
This Python script provides an easy-to-use utility for encrypting and decrypting files or folders. It supports creating encrypted `.enc` files for individual files and `tar.gz` archives for folders, making it suitable for secure storage and transfer of sensitive data.

---

## Features
- **File Encryption/Decryption**: Encrypts individual files into `.enc` format and decrypts them back to their original state.
- **Folder Encryption/Decryption**: Compresses folders into `.tar.gz`, encrypts the archive, and extracts it upon decryption.
- **Password-Based Security**: Uses AES encryption with a password-derived key.
- **Interactive and CLI Support**: Accepts command-line arguments or prompts for a password if not provided.

---

## Requirements
- Python 3.6+
- `cryptography` library

Install the required library with:
```bash
pip install cryptography
```

---

## Usage
### Command-line Arguments
```bash
python script.py <action> <path> [--password <password>]
```

### Arguments
- `<action>`: Either `encrypt` or `decrypt`.
- `<path>`: Path to the file or folder to process.
- `--password`: (Optional) Password for encryption/decryption. If not provided, the script will prompt for it.

### Examples
#### Encrypt a File
```bash
python script.py encrypt myfile.txt --password mysecurepassword
```
Output: `myfile.txt.enc`

#### Decrypt a File
```bash
python script.py decrypt myfile.txt.enc --password mysecurepassword
```
Output: `myfile.txt.dec`

#### Encrypt a Folder
```bash
python script.py encrypt myfolder --password mysecurepassword
```
Output: `myfolder.tar.gz.enc`

#### Decrypt a Folder
```bash
python script.py decrypt myfolder.tar.gz.enc --password mysecurepassword
```
Output: Extracted folder named `myfolder_decrypted`

---

## Security
- **Key Derivation**: Uses PBKDF2 with SHA-256 for secure key generation from the password.
- **Random Salt and IV**: Ensures that each encryption is unique, even with the same password.

---

## Building an Executable
Use `PyInstaller` to create a standalone executable:
```bash
pip install pyinstaller
pyinstaller --onefile script.py
```
The executable will be created in the `dist` directory.

---

## Notes
1. The script does not overwrite original files; new encrypted or decrypted files are created.
2. For folders, temporary `.tar.gz` archives are used for encryption and removed after processing.

---

## License
This script is open-source and available under the MIT License.

