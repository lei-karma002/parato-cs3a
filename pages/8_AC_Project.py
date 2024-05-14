import streamlit as st
import hashlib
from io import BytesIO
from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad
import base64

# Fixed key for symmetric encryption (16 bytes for AES-128, 8 bytes for DES, 16 or 24 bytes for 3DES)
AES_KEY = b'0123456789abcdef'
DES_KEY = b'12345678'
DES3_KEY = b'1234567890123456'  # 16 bytes key for DES3

def encrypt_text_symmetric(text, algorithm):
    if algorithm == "AES":
        key = AES_KEY
        cipher = AES.new(key, AES.MODE_CBC)
    elif algorithm == "DES":
        key = DES_KEY
        cipher = DES.new(key, DES.MODE_CBC)
    elif algorithm == "3DES":
        key = DES3_KEY
        cipher = DES3.new(key, DES3.MODE_CBC)
    else:
        return "Invalid algorithm"

    encrypted_text = cipher.encrypt(pad(text.encode(), cipher.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    encrypted_data = base64.b64encode(encrypted_text).decode('utf-8')
    return iv, encrypted_data

def decrypt_text_symmetric(iv, encrypted_data, algorithm):
    if algorithm == "AES":
        key = AES_KEY
        cipher = AES.new(key, AES.MODE_CBC, base64.b64decode(iv))
    elif algorithm == "DES":
        key = DES_KEY
        cipher = DES.new(key, DES.MODE_CBC, base64.b64decode(iv))
    elif algorithm == "3DES":
        key = DES3_KEY
        cipher = DES3.new(key, DES3.MODE_CBC, base64.b64decode(iv))
    else:
        return "Invalid algorithm"

    decrypted_text = unpad(cipher.decrypt(base64.b64decode(encrypted_data)), cipher.block_size).decode('utf-8')
    return decrypted_text

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

def download_file(data, filename):
    buffer = BytesIO()
    buffer.write(data.encode())
    buffer.seek(0)
    return st.download_button(label="Download", data=buffer, file_name=filename, mime="text/plain")

def main():
    st.title("Applied Cryptography Application")

    # Cryptographic operations
    operation = st.sidebar.selectbox("Select Operation", ["Encrypt", "Decrypt", "Hash"])

    # Text input
    text = st.text_area("Enter Text:")

    if operation == "Encrypt":
        encryption_type = st.selectbox("Select Encryption Algorithm", ["AES", "DES", "3DES"])
        if st.button("Encrypt"):
            if text:
                iv, encrypted_data = encrypt_text_symmetric(text, encryption_type)
                st.write("IV (Initialization Vector):", iv)
                st.write("Encrypted data:", encrypted_data)
                st.success("Text encrypted successfully!")
            else:
                st.warning("Please enter text to encrypt.")

    elif operation == "Decrypt":
        decryption_type = st.selectbox("Select Decryption Algorithm", ["AES", "DES", "3DES"])
        iv = st.text_input("Enter IV (Initialization Vector):")
        encrypted_data = st.text_area("Enter Encrypted Text:")
        if st.button("Decrypt"):
            if iv and encrypted_data:
                decrypted_text = decrypt_text_symmetric(iv, encrypted_data, decryption_type)
                st.write("Decrypted data:", decrypted_text)
                st.success("Text decrypted successfully!")
            else:
                st.warning("Please provide IV and encrypted text.")

    elif operation == "Hash":
        hash_function = st.selectbox("Select Hashing Algorithm", ["MD5", "SHA-1", "SHA-256", "SHA-3"])
        if st.button("Hash"):
            if text:
                hashed_text = hash_data(text, hash_function)
                st.success(f"{hash_function} hash:", hashed_text)
            else:
                st.warning("Please enter text to hash.")

if __name__ == "__main__":
    main()
