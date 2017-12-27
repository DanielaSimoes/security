from utils import generate_keys
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from diffiehellman.diffiehellman import DiffieHellman
import os
import pickle
from Crypto import Random

SERVER_PUB_KEY = os.path.dirname(os.path.abspath(__file__)) + "/server_public_key.pem"
RANDOM_ENTROPY_GENERATOR_SIZE = 32


class ClientCipher:

    def __init__(self):
        # store client app keys
        self.client_app_keys = generate_keys()

        # load server pub. key
        self.server_pub_key = RSA.importKey(open(SERVER_PUB_KEY).read())

    """
    ASYMMETRIC KEY CIPHER
    """

    def rsa_cipher(self, pub_key, raw_data):
        cipher = PKCS1_OAEP.new(pub_key)
        raw_data = pickle.dumps(raw_data)
        return cipher.encrypt(raw_data)

    def rsa_decipher(self, private_key, ciphered_data):
        key = RSA.importKey(open(private_key).read())
        cipher = PKCS1_OAEP.new(key)
        return pickle.loads(cipher.decrypt(ciphered_data))

    """
    SYMMETRIC KEY CIPHER
    """

    def sym_cipher(self, obj, ks):
        """

        :param obj: object to be ciphered
        :param ks: key to cipher the object
        """
        # pickle makes the serialization of the object
        picke_dumps = pickle.dumps([obj, os.urandom(RANDOM_ENTROPY_GENERATOR_SIZE)])

        iv = Random.get_random_bytes(8)
        obj = AES.new(ks, AES.MODE_CTR, iv)
        ciphered_obj = obj.encrypt(picke_dumps)

        return iv, ciphered_obj

    """
    HYBRID A-SYMMETRIC KEY CIPHER
    """

    def hybrid_cipher(self, obj, ks, public_key):
        # cipher using symmetric cipher AES CTR
        # returns the ciphered obj with the IV
        iv, ciphered_obj = self.sym_cipher(obj, ks)

        # key ciphered with the public_key
        key_encrypted = PKCS1_OAEP.new(public_key).encrypt(ks)

        return ciphered_obj, key_encrypted, iv

    def hybrid_random_key_cipher(self, obj, public_key):
        ks = Random.new().read(16)
        return self.hybrid_cipher(obj, ks, public_key)

    """
    CLIENT BOOTSTRAP SERVER NEGOTIATION
    """

    def negotiate_bootstrap(self, phase=1, val=None):
        """
        :param val:
        :param phase:
        :return:
        """
        if phase == 1:
            # client generate DH private and public key
            clientDH = DiffieHellman()
            clientDH.generate_public_key()

            # cipher DH public key with server pub. key

            dh_pub_ciphered = self.hybrid_random_key_cipher(clientDH.public_key, self.server_pub_key)
            print("ok")