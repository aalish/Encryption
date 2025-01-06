import os
import sys
import argparse
import getpass
import tarfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
import base64
import secrets

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, password):
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    iv = secrets.token_bytes(16)
    
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    output_file = file_path + ".enc"
    with open(output_file, 'wb') as f:
        f.write(salt + iv + ciphertext)

    print(f"Encrypted: {file_path} -> {output_file}")

def decrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        data = f.read()

    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32:]
    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    output_file = file_path.rstrip('.enc') + ".dec"
    with open(output_file, 'wb') as f:
        f.write(plaintext)

    print(f"Decrypted: {file_path} -> {output_file}")

def encrypt_folder(folder_path, password):
    tar_file = folder_path.rstrip(os.sep) + ".tar.gz"
    with tarfile.open(tar_file, "w:gz") as tar:
        tar.add(folder_path, arcname=os.path.basename(folder_path))
    print(f"Created tar.gz: {tar_file}")
    encrypt_file(tar_file, password)

    os.remove(tar_file)

def decrypt_folder(file_path, password):
    decrypt_file(file_path, password)
    decrypted_tar = file_path.rstrip('.enc') + ".dec"

    with tarfile.open(decrypted_tar, "r:gz") as tar:
        extract_path = file_path.rstrip('.enc') + "_decrypted"
        tar.extractall(path=extract_path)
    print(f"Decrypted and extracted: {decrypted_tar} -> {extract_path}")

    os.remove(decrypted_tar)

def main():
    parser = argparse.ArgumentParser(description="Encrypt or decrypt files and folders.")
    parser.add_argument("action", choices=['encrypt', 'decrypt'], help="Action to perform.")
    parser.add_argument("path", help="File or folder path.")
    parser.add_argument("--password", help="Password for encryption/decryption.")

    args = parser.parse_args()

    password = args.password
    if not password:
        password = getpass.getpass("Enter password: ")

    if os.path.isfile(args.path):
        if args.action == 'encrypt':
            encrypt_file(args.path, password)
        elif args.action == 'decrypt':
            decrypt_file(args.path, password)
    elif os.path.isdir(args.path):
        if args.action == 'encrypt':
            encrypt_folder(args.path, password)
        elif args.action == 'decrypt':
            decrypt_folder(args.path, password)
    else:
        print("Invalid path specified.")

if __name__ == "__main__":
    main()
