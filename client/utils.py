from Crypto.PublicKey import RSA


def generate_keys():
    keys = RSA.generate(2048)
    return keys


def export_public_key(keys):
    return keys.publickey().exportKey()


def load_pem():
    pass