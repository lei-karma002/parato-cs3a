import streamlit as st
import hashlib
from io import BytesIO
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.fernet import Fernet
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
            if algorithm == "SHA-1":
                st.success("Text hashed with SHA-1 successfully!")
            elif algorithm == "SHA-256":
                st.success("Text hashed with SHA-256 successfully!")
            elif algorithm == "SHA-3":
                st.success("Text hashed with SHA-3 successfully!")
            elif algorithm == "SHA-1":
                st.success("Text hashed with MD5 successfully!")

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

    encryption_option = st.radio("Select encryption method:", ("RSA", "Fernet"))
    encryption_input = st.text_input("Enter data to encrypt:")

    if st.button("Encrypt"):
        if encryption_option == "RSA":
            public_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            ).public_key()
            encrypted_data = encrypt_with_rsa(public_key, encryption_input)
            st.write("Encrypted Data (RSA):", encrypted_data.hex())
            st.success("Data encrypted with RSA successfully!")
        elif encryption_option == "Fernet":
            key = Fernet.generate_key()
            encrypted_data = encrypt_with_fernet(key, encryption_input)
            st.write("Encrypted Data (Fernet):", encrypted_data.decode())
            st.success("Data encrypted with Fernet successfully!")

if __name__ == "__main__":
    main()
