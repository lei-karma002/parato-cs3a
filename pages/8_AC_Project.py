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
        hash_value = hashlib.sha1(data).hexdigest().upper()
    elif algorithm == "SHA-256":
        hash_value = hashlib.sha256(data).hexdigest().upper()
    elif algorithm == "SHA-3":
        hash_value = hashlib.sha3_256(data).hexdigest().upper()
    elif algorithm == "MD5":
        hash_value = hashlib.md5(data).hexdigest().upper()
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

def prime_checker(p):
    if p < 2:
        return False
    if p == 2:
        return True
    if p % 2 == 0:
        return False
    for i in range(3, int(p**0.5) + 1, 2):
        if p % i == 0:
            return False
    return True

def primitive_check(g, p):
    required_set = set(num for num in range(1, p) if gcd(num, p) == 1)
    actual_set = set(pow(g, powers, p) for powers in range(1, p))
    return required_set == actual_set

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def diffie_hellman(p, g, private_key, received_public_key):
    public_key = pow(g, private_key, p)
    shared_secret = pow(received_public_key, private_key, p)
    shared_key = hashlib.sha256(str(shared_secret).encode()).digest()
    return public_key, shared_secret

def caesar_encrypt(message, key):
    encrypted = ''.join(chr((ord(char) + key - 32) % 95 + 32) for char in message)
    return encrypted

def caesar_decrypt(message, key):
    decrypted = ''.join(chr((ord(char) - key - 32) % 95 + 32) for char in message)
    return decrypted

def main():
    shared_secret = None  # Initialize shared_secret here
    
    st.title("APPLIED CRYPTOGRAPHY") #TITLE

    st.header("Hashing")

    input_type = st.radio("Select input type:", ("Text", "File"))

    if input_type == "Text":
        text = st.text_area("Enter text:")
        algorithm = st.selectbox("Select hashing algorithm:", ("SHA-1", "SHA-256", "SHA-3", "MD5"))
        
        if st.button("Hash Text"):
            hash_value = hash_data(text.encode(), algorithm)
            st.write(f"{algorithm} hash:", hash_value)
            if algorithm == "SHA-1":
                st.success("Text hashed with SHA-1 successfully!")
            elif algorithm == "SHA-256":
                st.success("Text hashed with SHA-256 successfully!")
            elif algorithm == "SHA-3":
                st.success("Text hashed with SHA-3 successfully!")
            elif algorithm == "MD5":
                st.success("Text hashed with MD5 successfully!")

    elif input_type == "File":
        file = st.file_uploader("Upload file:")
        if file is not None:
            file_contents = file.getvalue()
            algorithm = st.selectbox("Select hashing algorithm:", ("SHA-1", "SHA-256", "SHA-3", "MD5"))
        
            if st.button("Hash File"):
                hash_value = hash_data(file_contents, algorithm)
                st.write(f"{algorithm} hash:", hash_value)
                if algorithm == "SHA-1":
                    st.success("File hashed with SHA-1 successfully!")
                elif algorithm == "SHA-256":
                    st.success("File hashed with SHA-256 successfully!")
                elif algorithm == "SHA-3":
                    st.success("File hashed with SHA-3 successfully!")
                elif algorithm == "MD5":
                    st.success("File hashed with MD5 successfully!")
                
                # Add download button
                hashed_file = BytesIO(hash_value.encode())
                st.download_button(label="Download Hashed File", data=hashed_file, file_name="hashed_file.txt", mime="text/plain")
                
    st.header("Encryption")

    encryption_option = st.radio("Select encryption method:", ("RSA", "Fernet", "XOR Cipher"))

    if encryption_option == "RSA":
        encryption_input = st.text_input("Enter data to encrypt (RSA):")
    elif encryption_option == "Fernet":
        encryption_input = st.text_input("Enter data to encrypt (Fernet):")
    elif encryption_option == "XOR Cipher":
        encryption_input = st.text_input("Enter data to encrypt (XOR Cipher):")
        key = st.text_input("Enter XOR Cipher key:")
        block_size = st.number_input("Enter block size:", value=8, step=8, min_value=8, max_value=128)
        ciphertext, decrypted_data, key_bytes = xor_encrypt_and_decrypt(encryption_input, key, block_size)

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
        elif encryption_option == "XOR Cipher":
            st.write("Encrypted Data (XOR Cipher):", ciphertext.hex())
            st.write("Decrypted Data (XOR Cipher):", decrypted_data.decode())
            st.success("Data encrypted and decrypted with XOR Cipher successfully!")

    st.header("Diffie-Hellman")
    p = st.number_input("Enter prime number:", min_value=2, step=1, format="%d")
    g = st.number_input(f"Enter the primitive root of {p}:", min_value=2, step=1, format="%d")
    private_key = st.number_input("Enter your private key:", min_value=1, step=1, format="%d")
    received_public_key = st.number_input("Enter received public key:", min_value=1, step=1, format="%d")

    if st.button("Generate Public Key"):
        if not prime_checker(p):
            st.error("Number is not prime, please enter a prime number.")
        elif not primitive_check(g, p):
            st.error(f"Number is not a primitive root of {p}, please try again!")
        elif private_key >= p:
            st.error(f"Private key should be less than {p}, please enter again!")
        else:
            public_key, shared_secret = diffie_hellman(p, g, private_key, received_public_key)
            st.success(f"Your public key: {public_key}")
            st.success(f"Shared secret: {shared_secret}")

            message = st.text_input("Type your message:")
            if st.button("Send"):
                key = shared_secret % 95
                encrypted_message = caesar_encrypt(message, key)
                st.success(f"You Sent: {encrypted_message}")

            received_message = st.text_input("Enter received message:")
            if st.button("Receive"):
                key = shared_secret % 95
                decrypted_message = caesar_decrypt(received_message, key)
                st.success(f"Received message: {decrypted_message}")


    st.markdown("![Alt Text](https://tenor.com/view/shaq-shimmy-gif-6579961127426913411.gif)")

st.markdown("![Alt Text](https://tenor.com/view/hi-gif-14667427173248443855.gif)")
"""### We are the Group 8"""

if __name__ == "__main__":
    main()
