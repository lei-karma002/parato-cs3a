import streamlit as st
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.fernet import Fernet
import os

def hash_data(data, algorithm):
    try:
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
    except Exception as e:
        return f"Error: {e}"

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

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

def decrypt_with_rsa(private_key, encrypted_data):
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_data.decode()

def generate_fernet_key():
    return Fernet.generate_key()

def encrypt_with_fernet(key, data):
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode())
    return encrypted_data

def decrypt_with_fernet(key, encrypted_data):
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data.decode()

def main():
    st.title("Hashing and Encryption")

    encryption_option = st.radio("Select encryption method:", ("RSA", "Fernet"))

    if encryption_option == "RSA":
        private_key, public_key = generate_rsa_keys()

        text = st.text_area("Enter text:")
        algorithm = st.selectbox("Select hashing algorithm:", ("SHA-1", "SHA-256", "SHA-3", "MD5"))
        
        if st.button("Hash and Encrypt"):
            hash_value = hash_data(text, algorithm)
            encrypted_hash = encrypt_with_rsa(public_key, hash_value)
            st.write("Encrypted Hash:", encrypted_hash.hex())
            st.success("Text hashed and encrypted with RSA successfully!")

    elif encryption_option == "Fernet":
        key = generate_fernet_key()

        text = st.text_area("Enter text:")
        algorithm = st.selectbox("Select hashing algorithm:", ("SHA-1", "SHA-256", "SHA-3", "MD5"))
        
        if st.button("Hash and Encrypt"):
            hash_value = hash_data(text, algorithm)
            encrypted_hash = encrypt_with_fernet(key, hash_value)
            st.write("Encrypted Hash:", encrypted_hash.decode())
            st.success("Text hashed and encrypted with Fernet successfully!")

if __name__ == "__main__":
    main()
