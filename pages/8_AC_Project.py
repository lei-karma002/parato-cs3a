# AC
import streamlit as st
from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad
import hashlib
from io import BytesIO
import base64

# Fixed key for symmetric encryption (16 bytes for AES-128, 8 bytes for DES, 16 or 24 bytes for 3DES)
AES_KEY = b'0123456789abcdef'
DES_KEY = b'12345678'
DES3_KEY = b'1234567890123456'  # 16 bytes key for DES3

def encrypt_data(data, algorithm):
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

    ciphertext = cipher.encrypt(pad(data.encode(), cipher.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    encrypted_data = base64.b64encode(ciphertext).decode('utf-8')
    return iv, encrypted_data

def decrypt_data(iv, encrypted_data, algorithm):
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

    ciphertext = base64.b64decode(encrypted_data)
    decrypted_data = unpad(cipher.decrypt(ciphertext), cipher.block_size).decode('utf-8')
    return decrypted_data

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
    st.title("Hashing and Encryption")

    action = st.radio("Select action:", ("Hash", "Encrypt", "Decrypt"))

    if action == "Hash":
        text = st.text_area("Enter text:")
        algorithm = st.selectbox("Select hashing algorithm:", ("SHA-1", "SHA-256", "SHA-3", "MD5"))
        if st.button("Perform Hashing"):
            hash_value = hash_data(text, algorithm)
            st.write(f"{algorithm} hash:", hash_value)
            st.success("Text hashed successfully!")

    elif action == "Encrypt":
        plaintext = st.text_area("Enter text to encrypt:")
        algorithm = st.selectbox("Select encryption algorithm:", ("AES", "DES", "3DES"))
        if st.button("Encrypt"):
            iv, encrypted_data = encrypt_data(plaintext, algorithm)
            st.write("IV (Initialization Vector):", iv)
            st.write("Encrypted data:", encrypted_data)
            st.success("Text encrypted successfully!")

    elif action == "Decrypt":
        iv = st.text_input("Enter IV (Initialization Vector):")
        encrypted_data = st.text_area("Enter encrypted data:")
        algorithm = st.selectbox("Select decryption algorithm:", ("AES", "DES", "3DES"))
        if st.button("Decrypt"):
            decrypted_data = decrypt_data(iv, encrypted_data, algorithm)
            st.write("Decrypted data:", decrypted_data)
            st.success("Text decrypted successfully!")

if __name__ == "__main__":
    main()
