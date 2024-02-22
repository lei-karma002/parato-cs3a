import streamlit as st

# Streamlit app
st.header("Caesar Cipher Encryption and Decryption")

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
    if len(shift_keys) <= 1 or len(shift_keys) > len(text):
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
        else:
            result += char
        st.write(str(i) + " ", char, str(shift), result [i])
    return result

## Streamlit app
text = st.text_input("Text")
shift_keys_str = st.text_input("Shift keys (space-separated)")
shift_keys = [int(key) for key in shift_keys_str.split()]

if st.button("Submit"):
    if not shift_keys:
        st.error("Please enter shift keys.")
    else:
        encrypted_text = encrypt_decrypt(text, shift_keys, False)
        decrypted_text = encrypt_decrypt(encrypted_text, shift_keys, True)

        st.write("----------")
        st.write("Text:", text)
        st.write("Shift keys:", *shift_keys)
        st.write("Cipher:", encrypted_text)
        st.write("Decrypted text:", decrypted_text)
    st.snow()