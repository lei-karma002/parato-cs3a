import streamlit as st
import base64
import hashlib
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Symmetric encryption with Fernet
def generate_fernet_key():
    return Fernet.generate_key()

def encrypt_text_fernet(text, key):
    fernet = Fernet(key)
    return fernet.encrypt(text.encode())

def decrypt_text_fernet(encrypted_text, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_text).decode()

def encrypt_file_fernet(file_data, key):
    fernet = Fernet(key)
    return fernet.encrypt(file_data)

def decrypt_file_fernet(encrypted_file_data, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_file_data)

# Symmetric encryption with AES
def generate_aes_key():
    return AES.get_random_bytes(32)

def encrypt_text_aes(text, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

def decrypt_text_aes(encrypted_text, key):
    data = base64.b64decode(encrypted_text)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

def encrypt_file_aes(file_data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(file_data)
    return cipher.nonce + tag + ciphertext

def decrypt_file_aes(encrypted_file_data, key):
    nonce, tag, ciphertext = encrypted_file_data[:16], encrypted_file_data[16:32], encrypted_file_data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# Asymmetric encryption with RSA
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_text_rsa(text, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.encrypt(text)

def decrypt_text_rsa(encrypted_text, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(encrypted_text)

def encrypt_file_rsa(file_data, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.encrypt(file_data)

def decrypt_file_rsa(encrypted_file_data, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(encrypted_file_data)

# Hashing
def generate_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()

def generate_file_hash(file_data):
    return hashlib.sha256(file_data).hexdigest()

# Streamlit UI
def main():
    st.title("Applied Cryptography Application")

    operation = st.sidebar.selectbox("Select Operation", ["Encrypt", "Decrypt", "Generate Keys", "Hash Text", "Hash File"])
    action = st.radio("Choose Action Type", ["Text", "File"])

    if operation == "Encrypt":
        encryption_type = st.selectbox("Select Encryption Algorithm", ["Symmetric (Fernet)", "Symmetric (AES)", "Asymmetric (RSA)"])

        if encryption_type == "Symmetric (Fernet)":
            if st.checkbox("Generate Fernet Key"):
                key = generate_fernet_key().decode('utf-8')
                st.text_area("Generated Fernet Key:", key)
            else:
                key = st.text_area("Enter Fernet Key:")

            if action == "Text":
                text = st.text_area("Enter Text to Encrypt:")
                if st.button("Encrypt"):
                    if key and text:
                        try:
                            encrypted_text = encrypt_text_fernet(text, key.encode('utf-8'))
                            st.text_area("Encrypted Text:", encrypted_text.decode('utf-8'))
                        except Exception as e:
                            st.error(f"Encryption failed: {e}")
                    else:
                        st.warning("Please provide both key and text to encrypt.")

            elif action == "File":
                file = st.file_uploader("Choose a file to encrypt", type=None)
                if st.button("Encrypt"):
                    if key and file:
                        try:
                            file_data = file.read()
                            encrypted_file = encrypt_file_fernet(file_data, key.encode('utf-8'))
                            encrypted_file_name = f"encrypted_{file.name}"
                            st.download_button("Download Encrypted File", data=encrypted_file, file_name=encrypted_file_name)
                        except Exception as e:
                            st.error(f"File encryption failed: {e}")
                    else:
                        st.warning("Please provide both key and file to encrypt.")

        elif encryption_type == "Symmetric (AES)":
            if st.checkbox("Generate AES Key"):
                key = base64.b64encode(generate_aes_key()).decode('utf-8')
                st.text_area("Generated AES Key:", key)
            else:
                key = st.text_area("Enter AES Key (base64 encoded):")

            if action == "Text":
                text = st.text_area("Enter Text to Encrypt:")
                if st.button("Encrypt"):
                    if key and text:
                        try:
                            key_bytes = base64.b64decode(key)
                            encrypted_text = encrypt_text_aes(text, key_bytes)
                            st.text_area("Encrypted Text:", encrypted_text)
                        except Exception as e:
                            st.error(f"Encryption failed: {e}")
                    else:
                        st.warning("Please provide both key and text to encrypt.")

            elif action == "File":
                file = st.file_uploader("Choose a file to encrypt", type=None)
                if st.button("Encrypt"):
                    if key and file:
                        try:
                            key_bytes = base64.b64decode(key)
                            file_data = file.read()
                            encrypted_file = encrypt_file_aes(file_data, key_bytes)
                            encrypted_file_name = f"encrypted_{file.name}"
                            st.download_button("Download Encrypted File", data=encrypted_file, file_name=encrypted_file_name)
                        except Exception as e:
                            st.error(f"File encryption failed: {e}")
                    else:
                        st.warning("Please provide both key and file to encrypt.")

        elif encryption_type == "Asymmetric (RSA)":
            if 'rsa_keys_generated' not in st.session_state:
                st.session_state.rsa_keys_generated = False

            if st.button("Generate/Remove RSA Key Pair"):
                if st.session_state.rsa_keys_generated:
                    st.session_state.rsa_keys_generated = False
                    st.session_state.private_key = ""
                    st.session_state.public_key = ""
                else:
                    private_key, public_key = generate_rsa_keys()
                    st.session_state.private_key = private_key.decode('utf-8')
                    st.session_state.public_key = public_key.decode('utf-8')
                    st.session_state.rsa_keys_generated = True

            if st.session_state.rsa_keys_generated:
                st.text_area("Generated RSA Private Key:", st.session_state.private_key)
                st.text_area("Generated RSA Public Key:", st.session_state.public_key)

            public_key = st.text_area("Enter RSA Public Key:", st.session_state.public_key)

            if action == "Text":
                text = st.text_area("Enter Text to Encrypt:")
                if st.button("Encrypt"):
                    if public_key and text:
                        try:
                            encrypted_text = encrypt_text_rsa(text.encode('utf-8'), public_key.encode('utf-8'))
                            st.text_area("Encrypted Text:", base64.b64encode(encrypted_text).decode('utf-8'))
                        except Exception as e:
                            st.error(f"Encryption failed: {e}")
                    else:
                        st.warning("Please provide both public key and text to encrypt.")

            elif action == "File":
                file = st.file_uploader("Choose a file to encrypt", type=None)
                if st.button("Encrypt"):
                    if public_key and file:
                        try:
                            file_data = file.read()
                            encrypted_file = encrypt_file_rsa(file_data, public_key.encode('utf-8'))
                            encrypted_file_name = f"encrypted_{file.name}"
                            st.download_button("Download Encrypted File", data=encrypted_file, file_name=encrypted_file_name)
                        except Exception as e:
                            st.error(f"File encryption failed: {e}")
                    else:
                        st.warning("Please provide both public key and file to encrypt.")

    elif operation == "Decrypt":
        decryption_type = st.selectbox("Select Decryption Algorithm", ["Symmetric (Fernet)", "Symmetric (AES)", "Asymmetric (RSA)"])

        if decryption_type == "Symmetric (Fernet)":
            key = st.text_area("Enter Fernet Key:")

            if action == "Text":
                encrypted_text = st.text_area("Enter Encrypted Text:")
                if st.button("Decrypt"):
                    if key and encrypted_text:
                        try:
                            decrypted_text = decrypt_text_fernet(encrypted_text.encode('utf-8'), key.encode('utf-8'))
                            st.text_area("Decrypted Text:", decrypted_text)
                        except Exception as e:
                            st.error(f"Decryption failed: {e}")
                    else:
                        st.warning("Please provide both key and encrypted text to decrypt.")

            elif action == "File":
                file = st.file_uploader("Choose an encrypted file", type=None)
                if st.button("Decrypt"):
                    if key and file:
                        try:
                            file_data = file.read()
                            decrypted_file = decrypt_file_fernet(file_data, key.encode('utf-8'))
                            decrypted_file_name = f"decrypted_{file.name}"
                            st.download_button("Download Decrypted File", data=decrypted_file, file_name=decrypted_file_name)
                        except Exception as e:
                            st.error(f"File decryption failed: {e}")
                    else:
                        st.warning("Please provide both key and encrypted file to decrypt.")

        elif decryption_type == "Symmetric (AES)":
            key = st.text_area("Enter AES Key (base64 encoded):")

            if action == "Text":
                encrypted_text = st.text_area("Enter Encrypted Text:")
                if st.button("Decrypt"):
                    if key and encrypted_text:
                        try:
                            key_bytes = base64.b64decode(key)
                            decrypted_text = decrypt_text_aes(encrypted_text, key_bytes)
                            st.text_area("Decrypted Text:", decrypted_text)
                        except Exception as e:
                            st.error(f"Decryption failed: {e}")
                    else:
                        st.warning("Please provide both key and encrypted text to decrypt.")

            elif action == "File":
                file = st.file_uploader("Choose an encrypted file", type=None)
                if st.button("Decrypt"):
                    if key and file:
                        try:
                            key_bytes = base64.b64decode(key)
                            file_data = file.read()
                            decrypted_file = decrypt_file_aes(file_data, key_bytes)
                            decrypted_file_name = f"decrypted_{file.name}"
                            st.download_button("Download Decrypted File", data=decrypted_file, file_name=decrypted_file_name)
                        except Exception as e:
                            st.error(f"File decryption failed: {e}")
                    else:
                        st.warning("Please provide both key and encrypted file to decrypt.")

        elif decryption_type == "Asymmetric (RSA)":
            private_key = st.text_area("Enter RSA Private Key:")

            if action == "Text":
                encrypted_text = st.text_area("Enter Encrypted Text:")
                if st.button("Decrypt"):
                    if private_key and encrypted_text:
                        try:
                            decrypted_text = decrypt_text_rsa(base64.b64decode(encrypted_text.encode('utf-8')), private_key.encode('utf-8'))
                            st.text_area("Decrypted Text:", decrypted_text.decode('utf-8'))
                        except Exception as e:
                            st.error(f"Decryption failed: {e}")
                    else:
                        st.warning("Please provide both private key and encrypted text to decrypt.")

            elif action == "File":
                file = st.file_uploader("Choose an encrypted file", type=None)
                if st.button("Decrypt"):
                    if private_key and file:
                        try:
                            file_data = file.read()
                            decrypted_file = decrypt_file_rsa(file_data, private_key.encode('utf-8'))
                            decrypted_file_name = f"decrypted_{file.name}"
                            st.download_button("Download Decrypted File", data=decrypted_file, file_name=decrypted_file_name)
                        except Exception as e:
                            st.error(f"File decryption failed: {e}")
                    else:
                        st.warning("Please provide both private key and encrypted file to decrypt.")

    elif operation == "Generate Keys":
        key_type = st.selectbox("Select Key Type", ["Fernet", "AES", "RSA"])

        if key_type == "Fernet":
            key = generate_fernet_key().decode('utf-8')
            st.text_area("Generated Fernet Key:", key)

        elif key_type == "AES":
            key = base64.b64encode(generate_aes_key()).decode('utf-8')
            st.text_area("Generated AES Key (base64 encoded):", key)

        elif key_type == "RSA":
            if 'rsa_keys_generated' not in st.session_state:
                st.session_state.rsa_keys_generated = False

            if st.button("Generate/Remove RSA Key Pair"):
                if st.session_state.rsa_keys_generated:
                    st.session_state.rsa_keys_generated = False
                    st.session_state.private_key = ""
                    st.session_state.public_key = ""
                else:
                    private_key, public_key = generate_rsa_keys()
                    st.session_state.private_key = private_key.decode('utf-8')
                    st.session_state.public_key = public_key.decode('utf-8')
                    st.session_state.rsa_keys_generated = True

            if st.session_state.rsa_keys_generated:
                st.text_area("Generated RSA Private Key:", st.session_state.private_key)
                st.text_area("Generated RSA Public Key:", st.session_state.public_key)

    elif operation == "Hash Text":
        text = st.text_area("Enter Text to Hash:")
        if st.button("Generate Hash"):
            if text:
                hash_value = generate_hash(text)
                st.text_area("Generated Hash (SHA-256):", hash_value)
            else:
                st.warning("Please enter text to hash.")

    elif operation == "Hash File":
        file = st.file_uploader("Choose a file to hash", type=None)
        if st.button("Generate Hash"):
            if file:
                file_data = file.read()
                hash_value = generate_file_hash(file_data)
                st.text_area("Generated File Hash (SHA-256):", hash_value)
            else:
                st.warning("Please choose a file to hash.")

if __name__ == "__main__":
    main()
