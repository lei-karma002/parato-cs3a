import streamlit as st
import hashlib

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

if __name__ == "_main_":
    main()