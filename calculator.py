def fast_mod_exp(b, exp, m):
    return pow(b, exp, m)


def computeGCD(x, y):
    while (y):
        x, y = y, x % y
    return abs(x)


def findModInverse(a, m):
    if computeGCD(a, m) != 1:
        return None  # No mod inverse if a & m aren't relatively prime.
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3),
        v1, v2, v3
    return u1 % m

# def FastModularExponentiation(b, k, m):
#     return pow(b, pow(2, k), m)


def RSA_Encryption(priv_key, shared_large_prime, shared_primitive_root):
    pass


def Encrypt_RSA_Message(priv_key, public_key, shared_large_prime, shared_primitive_root):
    pass


def Decrypt_RSA_Message(priv_key, public_key, other_public_key, shared_large_prime, shared_primitive_root, encrypted_message):
    pass


class Diffie_Hellman_Key_Exchange:
    def __init__(self) -> None:
        pass

    def get_pub_key(self, priv_key, shared_large_prime, shared_primitive_root):
        public_key = fast_mod_exp(b=shared_primitive_root,
                                  exp=priv_key, m=shared_large_prime)
        return public_key

    def get_shared_secret(self, priv_key, others_public_key, shared_large_prime):
        shared_secret = fast_mod_exp(
            b=others_public_key, exp=priv_key, m=shared_large_prime)
        return shared_secret

    def encrypt_message(self, shared_secret, message, shared_large_prime):
        product = message, shared_secret
        encrypted_message = fast_mod_exp(
            b=product, exp=1, m=shared_large_prime)
        return encrypted_message

    def decrypt_message(self, shared_secret, encrypted_message, shared_large_prime):
        mod_inverse = findModInverse(a=shared_secret, m=shared_large_prime)
        message = encrypted_message * mod_inverse
        return message

class EncodeString:

    def __init__(self) -> None:
        pass

    def encode_string(self, string: str) -> int:
        value = 0
        exponent = 0
        base = 27
        for char in string:
            char_value = (ord(char) - ord('A') + 1) # A = 1, Z = 27
            value += char_value * pow(base, exponent)
            exponent += 1
        return value


def Problem_1():
    large_prime = 14348909
    primitive_root = 7691485
    alice_private_key = 919332
    encrypt = Diffie_Hellman_Key_Exchange
    # 1a
    alice_public_key = encrypt.get_pub_key(priv_key=alice_private_key,
                                           shared_large_prime=large_prime,
                                           shared_primitive_root=primitive_root)
    print("1a: Alice's public key: ", alice_public_key)

    # 1b
    print("----------")
    bob_private_key = 197992
    bob_public_key = encrypt.get_pub_key(priv_key=bob_private_key,
                                         shared_large_prime=large_prime,
                                         shared_primitive_root=primitive_root)
    
    print("1b: Bob's public key, which is sent to Alice to establish their shared secret key: ", bob_public_key)
    shared_secret = encrypt.get_shared_secret(
        priv_key=bob_private_key, others_public_key=alice_public_key, shared_large_prime=large_prime)
    print("1b: Shared secret")

    # 1c 
    print("----------")



def main():
    string_encoder = EncodeString
    print(string_encoder.encode_string("HI"))

main()
