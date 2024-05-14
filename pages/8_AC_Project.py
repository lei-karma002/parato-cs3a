import streamlit as st
import hashlib
from io import BytesIO
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

def pad(data, block_size):    
    padding_length = block_size - len(data) % block_size  
    padding = bytes([padding_length] * padding_length)  
    return data + padding                     
  
def unpad(data):
    padding_length = data[-1]                                
    assert padding_length > 0
    message, padding = data[:-padding_length], data[-padding_length:]
    assert all(p == padding_length for p  in padding)
    return message                       

def xor_encrypt_block(plaintext_block, key):
    encrypted_block = b''
    for i in range(len(plaintext_block)):
        encrypted_block += bytes([plaintext_block[i] ^ key[i % len(key)]])
    return encrypted_block                   

def xor_decrypt_block(ciphertext_block, key):
    return xor_encrypt_block(ciphertext_block, key)  

def xor_encrypt_and_decrypt(plaintext, key, block_size):
    key_bytes = pad(bytes(key.encode()), block_size)
    ciphertext = xor_encrypt(plaintext.encode(), key_bytes, block_size)
    decrypted_data = xor_decrypt(ciphertext, key_bytes, block_size)
    return ciphertext, decrypted_data, key_bytes

def xor_encrypt(plaintext, key, block_size):
    encrypted_data = b''
    padded_plaintext = pad(plaintext, block_size)
    for l, i in enumerate(range(0, len(padded_plaintext), block_size)):
        plaintext_block = padded_plaintext[i:i+block_size]
        encrypted_block = xor_encrypt_block(plaintext_block, key)
        encrypted_data += encrypted_block
    return encrypted_data                          

def xor_decrypt(ciphertext, key, block_size):
    decrypted_data = b''
    for l, i in enumerate(range(0, len(ciphertext), block_size)):
        ciphertext_block = ciphertext[i:i+block_size]
        decrypted_block = xor_decrypt_block(ciphertext_block, key)
        decrypted_data += decrypted_block
    unpadded_decrypted_data = unpad(decrypted_data)
    return unpadded_decrypted_data

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

    encryption_option = st.radio("Select encryption method:", ("RSA", "Fernet", "AES (Block Cipher)", "Caesar Cipher", "XOR"))
    encryption_input = st.text_input("Enter data to encrypt:")

    if encryption_option == "AES (Block Cipher)":
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
    elif encryption_option == "XOR":
        key_xor = st.text_input("Enter XOR key:")
        if encryption_input and key_xor:
            if st.button("Encrypt / Decrypt (XOR)"):
                ciphertext_xor, decrypted_data_xor, key_bytes_xor = xor_encrypt_and_decrypt(encryption_input, key_xor, 8)
                st.write("Encrypted Data (XOR):", ciphertext_xor.hex())
                st.write("Decrypted Data (XOR):", decrypted_data_xor)
        else:
            st.warning("Please provide XOR key and data to encrypt.")
    elif st.button("Encrypt"):
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
