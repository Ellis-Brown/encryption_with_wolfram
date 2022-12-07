# File is Python3

import get_exponent_mod_wolfram from wolfram


def fast_mod_exp(b, exp, m):
    if (exp < 10000000):
        return pow(b, exp, m)
    else:
        return get_exponent_mod_wolfram(b, exp, m)



    


def computeGCD(x, y):
    while (y):
        x, y = y, x % y
    return abs(x)


def findModInverse(a, m):
    # python 3.8+
    return pow(a, -1, m)

# def FastModularExponentiation(b, k, m):
#     return pow(b, pow(2, k), m)


class RSA_Encryption:

    def generate_key_pair(large_prime_1, large_prime_2):
        # To break this, factor the two numbers
        public_key = large_prime_1 * large_prime_2


    def generate_d(large_prime_1, large_prime_2, exponent):
        # D such that DE = 1 (mod (p-1)(q-1))
        d = pow(exponent, -1, (large_prime_1 - 1) * (large_prime_2 - 1))
        return d


    def encrypt_message(message, public_key, exponent):
        # C = M^e (mod n)
        if type(message) == str:
            message_value = EncodeString.encode_string(message)
        else:
            message_value = message
        print(message_value)
        # This line is taking a while. Wait for it
        print("Encrypting message...")
        encrypted_message = pow(message_value, exponent, public_key)
        print("Message encrypted!")
        
        return encrypted_message

    def decrypt_message(message_value, public_key, exponent, d):
        # M = C^d (mod n)
        print("Decrypting message...")
        decrypted_message = pow(message_value, d, public_key)
        print("Message decrypted!")
        return decrypted_message


class Diffie_Hellman_Key_Exchange:
    def __init__(self) -> None:
        pass

    def get_pub_key(priv_key, shared_large_prime, shared_primitive_root):
        public_key = fast_mod_exp(b=shared_primitive_root,
                                  exp=priv_key, m=shared_large_prime)
        return public_key

    def get_shared_secret(priv_key, others_public_key, shared_large_prime):
        shared_secret = fast_mod_exp(
            b=others_public_key, exp=priv_key, m=shared_large_prime)
        return shared_secret

    def encrypt_message(shared_secret, message, shared_large_prime):
        message = EncodeString.encode_string(message)
        product = message * shared_secret
        encrypted_message = fast_mod_exp(
            b=product, exp=1, m=shared_large_prime)
        return encrypted_message

    def decrypt_message(shared_secret, encrypted_message, shared_large_prime):
        mod_inverse = findModInverse(a=shared_secret, m=shared_large_prime)
        message_value = encrypted_message * mod_inverse % shared_large_prime
        message = EncodeString.decode_string(message_value)
        return message, message_value


class EncodeString:

    def __init__(self) -> None:
        pass

    def encode_string(string: str) -> int:
        value = 0
        exponent = 0
        base = 27
        for char in string[::-1]:
            char_value = (ord(char) - ord('A') + 1)  # A = 1, Z = 27
            value += char_value * pow(base, exponent)
            exponent += 1
        return value

    def decode_string(value: int) -> str:
        # Find the remainder of the value divided by 27
        # Find the quotient of the value divided by 27
        if value % 27 == 0:
            return ""
        else:
            return EncodeString.decode_string(value // 27) + chr((value % 27) + ord('A') - 1)


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
    print("1b: Shared secret: ", shared_secret)

    # 1c
    print("----------")
    message = "NMTHY"  # yes, this is the message.
    encrypted_message = encrypt.encrypt_message(shared_secret=shared_secret,
                                                message=message, 
                                                shared_large_prime=large_prime)
    print("1c: Message value: ", EncodeString.encode_string(message))
    print("1c: Encrypted message: ", encrypted_message)

    # 1d
    encrypted_message_2 = 8730216
    print("----------")
    message, message_value = encrypt.decrypt_message(
        shared_secret=shared_secret, encrypted_message=encrypted_message_2, shared_large_prime=large_prime)
    print("1d: Decrypted message: ", message)
    print("1d: Decrypted message value: ", message_value)

def Problem_2():
    rsa = RSA_Encryption
    large_prime_p = 20359
    large_prime_q = 10939
    exponent = 119102437

    # 2a 
    alice_public_key = rsa.generate_key_pair(large_prime_p, large_prime_q)
    print("2a: Alice's public key: ", alice_public_key)

    # 2b
    print("----------")
    message_value = 12345 
    encrypted_message = rsa.encrypt_message(message=message_value, public_key=alice_public_key, exponent=exponent)
    print("2b: Encrypted message: ", encrypted_message)

    # 2c
    print("----------")
    encrypted_message_2 = 163527889 
    d = rsa.generate_d(large_prime_p, large_prime_q, exponent)
    decrypted_message = rsa.decrypt_message(message_value=encrypted_message_2, public_key=alice_public_key, exponent=exponent, d=d)
    print("2c: Decrypted message: ", decrypted_message)



def main():
    print("*************************")
    print("\tProblem 1")
    print("*************************")
    Problem_1()
    
    print("\n\n")

    print("*************************")
    print("\tProblem 2")
    print("*************************")
    Problem_2()



main()
