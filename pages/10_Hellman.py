import streamlit as st
import hashlib

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
    st.title("Secure Chat with Diffie-Hellman Key Exchange")

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

if __name__ == "__main__":
    main()