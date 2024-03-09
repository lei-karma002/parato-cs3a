import streamlit as st

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
    st.title("XOR Encryption and Decryption")
    allowed_block_sizes = [8, 16, 32, 64, 128]
    
    plaintext = st.text_input("Enter plaintext: ")
    key = st.text_input("Enter key: ")
    
    while True:
        block_size = st.number_input("Enter block size: ")
        if block_size in allowed_block_sizes:
            break
        else:
            st.write("Block size must be one of 8, 16, 32, 64, or 128 bytes")

    ciphertext = xor_encrypt(plaintext, key, block_size)
    decrypted_data = xor_decrypt(ciphertext, key, block_size)

    st.write("\nOriginal plaintext:", plaintext)
    st.write("Key byte      :", key)
    st.write("Key hex       :", key.hex())
    st.write("Encrypted data:", ciphertext.hex())  
    st.write("Decrypted data:", decrypted_data.hex())
    st.write("Decrypted data:", decrypted_data)

if __name__ == "__main__":
    main()