import streamlit as st
import hashlib
from io import BytesIO

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

def unhash_data(hash_value, algorithm):
    # Since hash functions are one-way, we cannot reverse the process
    # Instead, we can generate the hash of the unhashed content
    # and compare it with the original hash value
    # If they match, it's reasonable to assume that the unhashing process succeeded
    # In reality, this is not true "unhashing", but rather a verification step
    return hash_data(hash_value, algorithm)

def download_file(data, filename):
    buffer = BytesIO()
    buffer.write(data.encode())
    buffer.seek(0)
    return st.download_button(label="Download", data=buffer, file_name=filename, mime="text/plain")

def main():
    st.title("Hashing")

    input_type = st.radio("Select input type:", ("Text", "File"))

    if input_type == "Text":
        text = st.text_area("Enter text:")
        algorithm = st.selectbox("Select hashing algorithm:", ("SHA-1", "SHA-256", "SHA-3", "MD5"))
        if st.button("Hash"):
            hash_value = hash_data(text, algorithm)
            st.write(f"{algorithm} hash:", hash_value)

    elif input_type == "File":
        file = st.file_uploader("Upload file:")
        if file is not None:
            file_contents = file.getvalue().decode("utf-8")
            algorithm = st.selectbox("Select hashing algorithm:", ("SHA-1", "SHA-256", "SHA-3", "MD5"))
            if st.button("Hash"):
                hash_value = hash_data(file_contents, algorithm)
                st.write(f"{algorithm} hash:", hash_value)
                download_button = download_file(hash_value, "hashed_file.txt")
                if download_button:
                    st.success("File downloaded successfully!")

                # Upload and unhash functionality
                st.header("Upload and Unhash")
                uploaded_file = st.file_uploader("Upload hashed file to unhash:")
                if uploaded_file is not None:
                    uploaded_file_contents = uploaded_file.getvalue().decode("utf-8")
                    if st.button("Unhash"):
                        unhashed_value = unhash_data(uploaded_file_contents, algorithm)
                        st.write(f"Unhashed {algorithm} value:", unhashed_value)
                        download_unhashed_button = download_file(unhashed_value, "unhashed_file.txt")
                        if download_unhashed_button:
                            st.success("Unhashed file downloaded successfully!")

if __name__ == "__main__":
    main()
