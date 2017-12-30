# encoding: utf-8
import os
import pkcs11
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as _aspaadding
import getpass
from OpenSSL import crypto
from pem import parse_file
import hashlib


class CitizenCard:
    """
    - Deciphering using the Private Key of the Portuguese Citizen Card is not currently supported, the code
    to be used: https://github.com/danni/python-pkcs11/blob/master/docs/opensc.rst

    """

    def __init__(self, pin=None):
        if pin is None:
            self.pin = getpass.getpass("Auth PIN (CARTAO DE CIDADAO): ")
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
        with self.token.open(user_pin=self.pin) as session:
            priv = session.get_key(pkcs11.constants.ObjectClass.PRIVATE_KEY,
                                   pkcs11.KeyType.RSA, 'CITIZEN AUTHENTICATION KEY')

            return priv.decrypt(data, mechanism=pkcs11.Mechanism.SHA256_RSA_PKCS)

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

    def get_available_certs_labels(self):
        certs_labels = []

        with self.token.open(user_pin=self.pin) as session:
            # get public key certificates
            for cert in session.get_objects({pkcs11.constants.Attribute.CLASS:
                                             pkcs11.constants.ObjectClass.CERTIFICATE}):

                label = cert[pkcs11.constants.Attribute.LABEL]
                certs_labels.append(label)

        return certs_labels

    @staticmethod
    def verify(message, sign_bytes, x509_pem):
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
        cert = x509.load_pem_x509_certificate(x509_pem, default_backend())
        # Extract public key from certificate
        sign_cert_pk = cert.public_key()

        # encrypt message
        return sign_cert_pk.encrypt(message, _aspaadding.OAEP(
                                       mgf=_aspaadding.MGF1(algorithm=hashes.SHA256()),
                                       algorithm=hashes.SHA256(),
                                       label=None
                                    ))

    @staticmethod
    def validate_chain(chain, pem_certificate, ssl_ca_root_file="./utils/mozilla-ca-bundle.txt"):
        # parse CA roots certificate PEMs to an list
        trusted_certs_pems = parse_file(ssl_ca_root_file)

        # create a new store
        store = crypto.X509Store()

        # check middle CAs for revocation
        store.set_flags(crypto.X509StoreFlags.CRL_CHECK)

        # check just the certificate CRL and not if all certificates up to the root are revoked
        # not recommended since requires all CAs root revogations
        store.set_flags(crypto.X509StoreFlags.CRL_CHECK_ALL)

        # add system trusted CA roots to store
        for pem_crt in trusted_certs_pems:
            store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, pem_crt.as_bytes()))

        # load supplied chain
        for pem_crt in chain:
            store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, pem_crt))

        # convert pem to OpenSSL certificate format
        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, pem_certificate)

        # validate full chain
        store_ctx = crypto.X509StoreContext(store, certificate)

        # load CRLs to the store
        for crl in [f for f in os.listdir("utils/crls") if os.path.isfile(os.path.join("utils/crls", f))]:
            store.add_crl(crypto.load_crl(crypto.FILETYPE_PEM, open(os.path.join("utils/crls", crl), "r").read()))

        store_ctx.verify_certificate()

    def generate_uuid(self):
        pem = self.get_certificate_pem()
        return hashlib.sha224(pem).hexdigest()


if __name__ == '__main__':
    pin = "3885"
    cc = CitizenCard(pin=pin)
    data = b'INPUT'
    signature = cc.sign(data)

    # x509 PEM CERTIFICATE
    x509_pem = cc.get_certificate_pem()
    cc.verify(data, signature, x509_pem)

    # encrypt data
    x509_pem = cc.get_certificate_pem()
    data_ciphered = cc.encrypt(data, x509_pem)

    # cc.decrypt(data_ciphered)
    x509_chain = [cc.get_certificate_pem(label=label) for label in cc.get_available_certs_labels()]

    for label in cc.get_available_certs_labels():
        x509_certificate = cc.get_certificate_pem(label=label)

        cert_file = 'utils/crts/%s.pem' % label
        f = open(cert_file, 'wb')
        f.write(x509_certificate)
        f.close()

    cc.validate_chain(chain=x509_chain, pem_certificate=x509_pem)

    print(cc.get_certificate_pem())
    print(cc.get_public_key_pem())
    print("ok")
