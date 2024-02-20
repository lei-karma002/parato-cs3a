import streamlit as st

def encrypt_decrypt(text, shift_keys, ifdecrypt):
    """
    Encrypts or decrypts a text using Caesar Cipher with a list of shift keys.
    Args:
        text: The text to encrypt or decrypt.
        shift_keys: A list of integers representing the shift values for each character.
        ifdecrypt: Flag indicating whether to decrypt or encrypt.
    Returns:
        A string containing the encrypted or decrypted text.
    """

    result = ""
    details = []

    if len(shift_keys) <= 0:
        raise ValueError("Invalid shift keys length")

    for i, char in enumerate(text):
        shift = shift_keys[i % len(shift_keys)]

        if 32 <= ord(char) <= 125:
            new_ascii = ord(char) + shift if not ifdecrypt else ord(char) - shift
            while new_ascii > 125:
                new_ascii -= 94
            while new_ascii < 32:
                new_ascii += 94

            result += chr(new_ascii)
            details.append((char, shift, chr(new_ascii)))
        else:
            result += char
            details.append((char, shift, char))

    return result, details

# Streamlit app
st.title("Caesar Cipher Encryption and Decryption")

text = st.text_input("Enter the text:")
shift_keys_str = st.text_input("Enter the shift keys (space-separated):")
decrypt_checkbox = st.checkbox("Decrypt")
submit_button = st.button("Submit")

if submit_button:
    if shift_keys_str:
        shift_keys = [int(key) for key in shift_keys_str.split()]
        if decrypt_checkbox:
            result, details = encrypt_decrypt(text, shift_keys, ifdecrypt=True)
        else:
            result, details = encrypt_decrypt(text, shift_keys, ifdecrypt=False)

        st.write("Text:", text)
        st.write("Shift keys:", *shift_keys)
        st.write("Cipher:", result)
        st.write("Details:")
        st.write("Index Char Shift Result")
        for idx, (char, shift, res) in enumerate(details):
            st.write(f"{idx} {char} {shift} {res}")
