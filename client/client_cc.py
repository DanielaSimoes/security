import os
import pkcs11
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as _aspaadding
import getpass


class CitizenCard:

    def __init__(self, pin=None):
        if pin is None:
            self.pin = getpass.getpass("Signature PIN: ")
        else:
            self.pin = pin

        lib = pkcs11.lib(os.getenv('PKCS11_MODULE',  "/usr/local/lib/opensc-pkcs11.dylib"))
        self.token = lib.get_token(token_label='Auth PIN (CARTAO DE CIDADAO)')

    def inserted(self):
        with self.token.open(user_pin=self.pin) as session:
            return False if session is None else True

    def sign(self, data):
        with self.token.open(user_pin=self.pin) as session:
            priv = session.get_key(pkcs11.constants.ObjectClass.PRIVATE_KEY,
                                   pkcs11.KeyType.RSA, 'CITIZEN AUTHENTICATION KEY')

            return priv.sign(data, mechanism=pkcs11.Mechanism.SHA256_RSA_PKCS)

    def decrypt(self, data):
        pass

    def get_certificate(self, label="CITIZEN AUTHENTICATION CERTIFICATE"):
        with self.token.open(user_pin=self.pin) as session:
            # get public key certificates
            for cert in session.get_objects({pkcs11.constants.Attribute.CLASS: pkcs11.constants.ObjectClass.CERTIFICATE,
                                             pkcs11.constants.Attribute.LABEL: label}):
                value = cert[pkcs11.constants.Attribute.VALUE]
                return x509.load_der_x509_certificate(value, default_backend())

    def get_certificate_pem(self, label="CITIZEN AUTHENTICATION CERTIFICATE"):
            return self.get_certificate(label).public_bytes(Encoding.PEM)

    def get_public_key(self, label="CITIZEN AUTHENTICATION CERTIFICATE"):
        with self.token.open(user_pin=self.pin) as session:
            # get public key certificates
            for cert in session.get_objects({pkcs11.constants.Attribute.CLASS: pkcs11.constants.ObjectClass.CERTIFICATE,
                                             pkcs11.constants.Attribute.LABEL: label}):

                value = cert[pkcs11.constants.Attribute.VALUE]
                cert = x509.load_der_x509_certificate(value, default_backend())

                return cert.public_key()

    def get_public_key_pem(self, label="CITIZEN AUTHENTICATION CERTIFICATE"):
            return self.get_public_key(label).public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

    def verify(self, message, sign_bytes, x509_pem):
        cert = x509.load_pem_x509_certificate(x509_pem, default_backend())
        # Extract public key from certificate
        sign_cert_pk = cert.public_key()

        # Generate an verification context from the given public key and signature
        verifier = sign_cert_pk.verifier(
            sign_bytes,
            _aspaadding.PKCS1v15(),
            hashes.SHA256()
        )

        # Validates if the signature was performed using the given certificate and message
        verifier.update(message)
        return verifier.verify()

    def encrypt(self, message, x509_pem):
        pass


if __name__ == '__main__':
    pin = "3885"
    cc = CitizenCard(pin=pin)
    data = b'INPUT'
    signature = cc.sign(data)

    # x509 PEM CERTIFICATE
    x509_pem = cc.get_certificate_pem()
    cc.verify(data, signature, x509_pem)

    print(cc.get_certificate_pem())
    print(cc.get_public_key_pem())
    print("ok")
