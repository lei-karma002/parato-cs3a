import streamlit as st
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def hash_data(data, algorithm):
    if algorithm == "SHA-1":
        hash_value = hashlib.sha1(data.encode()).hexdigest().upper()
    elif algorithm == "SHA-256":
        hash_value = hashlib.sha256(data.encode()).hexdigest().upper()
    elif algorithm == "SHA-3":
        hash_value = hashlib.sha3_256(data.encode()).hexdigest().upper()
    elif algorithm == "MD5":
        hash_value = hashlib.md5(data.encode()).hexdigest().upper()
    else:
        return "Invalid algorithm"
    return hash_value

def encrypt_with_rsa(public_key, data):
    encrypted_data = public_key.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data

def encrypt_with_fernet(key, data):
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode())
    return encrypted_data

def encrypt_block_cipher(key, plaintext):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext

def decrypt_block_cipher(key, ciphertext):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def caesar_cipher(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
                elif shifted < ord('a'):
                    shifted += 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
                elif shifted < ord('A'):
                    shifted += 26
            result += chr(shifted)
        else:
            result += char
    return result

def main():
    st.title("APPLIED CRYPTOGRAPHY")

    st.header("Hashing")

    input_type = st.radio("Select input type:", ("Text", "File"))

    if input_type == "Text":
        text = st.text_area("Enter text:")
        algorithm = st.selectbox("Select hashing algorithm:", ("SHA-1", "SHA-256", "SHA-3", "MD5"))
        
        if st.button("Hash"):
            hash_value = hash_data(text, algorithm)
            st.write(f"{algorithm} hash:", hash_value)
            st.success("Text hashed successfully!")

    elif input_type == "File":
        file = st.file_uploader("Upload file:")
        if file is not None:
            file_contents = file.getvalue().decode("utf-8")
            algorithm = st.selectbox("Select hashing algorithm:", ("SHA-1", "SHA-256", "SHA-3", "MD5"))
        
            if st.button("Hash"):
                hash_value = hash_data(file_contents, algorithm)
                st.write(f"{algorithm} hash:", hash_value)
                st.success("File hashed successfully!")
                
    st.header("Encryption")

    encryption_option = st.radio("Select encryption method:", ("RSA", "Fernet", "AES (Block Cipher)", "Caesar Cipher"))
    encryption_input = st.text_input("Enter data to encrypt:")

    if encryption_option == "RSA":
        if encryption_input:
            public_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            ).public_key()
            encrypted_data = encrypt_with_rsa(public_key, encryption_input)
            st.write("Encrypted Data (RSA):", encrypted_data.hex())
        else:
            st.warning("Please provide data to encrypt.")

    elif encryption_option == "Fernet":
        key = Fernet.generate_key()
        if encryption_input:
            encrypted_data = encrypt_with_fernet(key, encryption_input)
            st.write("Encrypted Data (Fernet):", encrypted_data.decode())
        else:
            st.warning("Please provide data to encrypt.")

    elif encryption_option == "AES (Block Cipher)":
        aes_key = st.text_input("Enter AES key (16, 24, or 32 bytes):")
        if encryption_input and aes_key:
            if st.button("Encrypt (AES)"):
                ciphertext_block = encrypt_block_cipher(aes_key.encode(), encryption_input.encode())
                st.write("Ciphertext (AES):", ciphertext_block.hex())
        else:
            st.warning("Please provide AES key and data to encrypt.")

    elif encryption_option == "Caesar Cipher":
        caesar_shift = st.number_input("Enter Caesar cipher shift:", min_value=1, max_value=25, value=3)
        if encryption_input:
            if st.button("Encrypt (Caesar)"):
                ciphertext_caesar = caesar_cipher(encryption_input, caesar_shift)
                st.write("Ciphertext (Caesar):", ciphertext_caesar)
        else:
            st.warning("Please provide plaintext.")

if __name__ == "__main__":
    main()
