import streamlit as st
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.fernet import Fernet


# Function to encrypt text using symmetric encryption
def encrypt_text_symmetric(text, key):
    cipher_suite = Fernet(key)
    encrypted_text = cipher_suite.encrypt(text.encode())
    return encrypted_text

# Function to decrypt text using symmetric encryption
def decrypt_text_symmetric(encrypted_text, key):
    cipher_suite = Fernet(key)
    decrypted_text = cipher_suite.decrypt(encrypted_text).decode()
    return decrypted_text

# Function to encrypt text using asymmetric encryption
def encrypt_text_asymmetric(text, public_key):
    public_key = serialization.load_pem_public_key(public_key, backend=default_backend())
    encrypted_text = public_key.encrypt(text.encode(), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return encrypted_text

# Function to decrypt text using asymmetric encryption
def decrypt_text_asymmetric(encrypted_text, private_key):
    private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
    decrypted_text = private_key.decrypt(encrypted_text, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)).decode()
    return decrypted_text

# Streamlit UI
def main():
    st.title("Applied Cryptography Application")

    # Cryptographic operations
    operation = st.sidebar.selectbox("Select Operation", ["Encrypt", "Decrypt"])

    # Text input
    text = st.text_area("Enter Text:")

    if operation == "Encrypt":
        encryption_type = st.selectbox("Select Encryption Algorithm", ["AES", "DES", "RC4", "RSA"])
        if encryption_type != "RSA":
            key = Fernet.generate_key()
            if st.button("Encrypt"):
                if text:
                    if encryption_type in ["AES", "DES", "RC4"]:
                        encrypted_text = encrypt_text_symmetric(text, key)
                        st.success("Encrypted Text: " + str(encrypted_text))
                else:
                    st.warning("Please enter text to encrypt.")
        else:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            public_key = key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
            if st.button("Encrypt"):
                if text:
                    encrypted_text = encrypt_text_asymmetric(text, public_key)
                    st.success("Encrypted Text: " + str(encrypted_text))
                else:
                    st.warning("Please enter text to encrypt.")

    elif operation == "Decrypt":
        decryption_type = st.selectbox("Select Decryption Algorithm", ["Symmetric (Fernet)", "Asymmetric (RSA)"])
        if decryption_type == "Symmetric (Fernet)":
            key = st.text_input("Enter Key:")
            encrypted_text = st.text_area("Enter Encrypted Text:")
            if st.button("Decrypt"):
                if key and encrypted_text:
                    decrypted_text = decrypt_text_symmetric(encrypted_text.encode(), key.encode())
                    st.success("Decrypted Text: " + decrypted_text)
                else:
                    st.warning("Please provide both key and encrypted text.")
        else:
            private_key = st.text_area("Enter Private Key:")
            encrypted_text = st.text_area("Enter Encrypted Text:")
            if st.button("Decrypt"):
                if private_key and encrypted_text:
                    decrypted_text = decrypt_text_asymmetric(encrypted_text.encode(), private_key.encode())
                    st.success("Decrypted Text: " + decrypted_text)
                else:
                    st.warning("Please provide both private key and encrypted text.")

if __name__ == "__main__":
    main()
