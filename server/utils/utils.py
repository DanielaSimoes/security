from Crypto.PublicKey import RSA


def generate_keys():
    keys = RSA.generate(2048)
    return keys
