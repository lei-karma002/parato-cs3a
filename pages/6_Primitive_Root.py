import streamlit as st

def is_prime(num):
    if num < 2:
        return False
    for i in range(2, int(num ** 0.5) + 1):
        if num % i == 0:
            return False
    return True

def compute_modulus(base, exponent, mod):
    result = 1
    for _ in range(exponent):
        result = (result * base) % mod
    return result

def get_primitive_roots(p):
    primitive_roots = []
    for g in range(1, p):
        is_primitive_root = True
        powers = set()
        for j in range(1, p):
            res = compute_modulus(g, j, p)
            powers.add(res)
            if res == 1:
                break
        if len(powers) == p - 1:
            primitive_roots.append(g)
    return primitive_roots

def print_primitive_roots(p, primitive_number):
    if not is_prime(p):
        st.write(f"{p} is not a prime number!!")
        return
    
    print_results = []
    for g in range(1, p):
        output = []
        for j in range(1, p):
            res = compute_modulus(g, j, p)
            output.append(f"{g}^{j} mod {p} = {res}")
            if res == 1:
                break
        if g in get_primitive_roots(p):
            output[-1] += f" ==> {g} is primitive root of {p},"
        else:
            output[-1] += ","
        print_results.append(", ".join(output).rstrip())
    
    st.write("\n".join(print_results))
    primitive_roots = get_primitive_roots(p)
    if primitive_roots:
        if primitive_number in primitive_roots:
            st.write(f"{primitive_number} is primitive root: True {primitive_roots}")
        else:
            st.write(f"{primitive_number} is NOT primitive root of {p} - List of Primitive roots: {primitive_roots}")
    else:    
        st.write(f"{primitive_number} is NOT primitive root of {p} - List of Primitive roots: {primitive_roots}")

def main():
    st.title("Primitive Roots")

    p = st.number_input("Enter a prime number (p):", min_value=2, step=1)
    primitive_number = st.number_input("Enter a primitive number:", min_value=1, step=1)

    if st.button("Find Primitive Roots"):
        print_primitive_roots(int(p), int(primitive_number))

if __name__ == "__main__":
    main()