from client_actions import ClientActions
from client_cc import CitizenCard
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.hashes import SHA256, SHA512
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os, errno


class Client:
    def __init__(self):
        mode = input("Cipher Mode: (CTR, CFB, OFB): \n")

        if mode == "CTR":
            mode = modes.CTR
        elif mode == "CFB":
            mode = modes.CFB
        elif mode == "OFB":
            mode = modes.OFB
        else:
            print("Wrong input!")
            exit(1)

        hmac_hash_type = input("HMAC Hash Type: (SHA256, SHA512): \n")

        if hmac_hash_type == "SHA256":
            hmac_hash_type = SHA256
        elif hmac_hash_type == "SHA512":
            hmac_hash_type = SHA512
        else:
            print("Wrong input!")
            exit(1)

        print("Making a secure channel with the server...")

        self.cc = CitizenCard()
        self.client = ClientActions(mode, hmac_hash_type, self.cc)

        # generate the uuid of the user
        print("Generating a UUID based in your citizen card...")
        self.uuid = self.cc.generate_uuid()
        print("Your client UUID is: %s " % self.uuid)

        print("Verifying if you already have your keys...")

        # user keys
        self.private_key = None
        self.public_key = None
        self.private_key_pem = None
        self.public_key_pem = None
        self.user_asym_keys()

        rsp = self.client.create(self.uuid, self.public_key_pem)

        if "result" in rsp:
            self.server_id = rsp["result"]
            print("Your account is being created...")
        else:
            print("You have logged in.")
            self.server_id = self.client.get_server_id(self.uuid)["result"]

        while self.menu():
            pass

    def user_asym_keys(self):
        if not os.path.exists('utils/user_keys/%s/private_key.pem' % self.uuid):
            try:
                os.makedirs('utils/user_keys/%s' % self.uuid)
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise

            # create private key
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )

            pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )

            """ cipher the stored private key """
            # sign the uuid (known and unique value)
            signature = self.cc.sign(self.uuid)

            # cipher the stored key
            ciphered_key_pem = self.client.client_cipher.sym_cipher(pem, signature[0:32], signature[32:48], modes.CTR)[1]  # return 0 -> iv, 1-> ciphered obj

            # store key
            self.private_key_pem = pem
            private_file = 'utils/user_keys/%s/private_key.pem' % self.uuid
            f = open(private_file, 'wb')
            f.write(ciphered_key_pem)
            f.close()
        else:
            # load private key
            tmp = open('utils/user_keys/%s/private_key.pem' % self.uuid, "rb").read()

            # sign the uuid (known and unique value)
            signature = self.cc.sign(self.uuid)

            self.private_key_pem = self.client.client_cipher.sym_decipher(tmp, signature[0:32], signature[32:48], modes.CTR)

            self.private_key = serialization.load_pem_private_key(self.private_key_pem, password=None,
                                                                  backend=default_backend())

        if not os.path.exists('utils/user_keys/%s/public_key.pem' % self.uuid):
            try:
                os.makedirs('utils/user_keys/%s' % self.uuid)
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise

            # public key
            self.public_key = self.private_key.public_key()

            pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            """ cipher the stored public key """
            # sign the uuid (known and unique value)
            signature = self.cc.sign(self.uuid)

            # cipher the stored key
            ciphered_key_pem = self.client.client_cipher.sym_cipher(pem, signature[0:32], signature[32:48], modes.CTR)[1]  # return 0 -> iv, 1-> ciphered obj

            self.public_key_pem = pem
            public_file = 'utils/user_keys/%s/public_key.pem' % self.uuid
            f = open(public_file, 'wb')
            f.write(ciphered_key_pem)
            f.close()
        else:
            tmp = open('utils/user_keys/%s/public_key.pem' % self.uuid, "rb").read()

            # sign the uuid (known and unique value)
            signature = self.cc.sign(self.uuid)

            self.public_key_pem = self.client.client_cipher.sym_decipher(tmp, signature[0:32], signature[32:48], modes.CTR)

            # load public key
            self.public_key = serialization.load_pem_public_key(self.public_key_pem, backend=default_backend())

    def menu(self):
        print("OPTIONS AVAILABLE:")
        print("1 - Send a message")
        print("2 - Verify new messages")
        print("3 - List peers")
        print("4 - List sent messages")
        print("5 - Exit")
        option = int(input("Option: "))

        print("-------------------------")

        if option == 1:
            peer_to_connect = str(input("Write the UUID of the peer you want to send a message:"))
            server_id_peer = self.client.get_server_id(peer_to_connect)["result"]
            if server_id_peer is None:
                print("The peer is not registered in the server.")
            else:
                message = str(input("Write your message:"))

                rsp = self.client.send(self.server_id, server_id_peer, message, self.public_key)
                if "result" in rsp and len(rsp["result"]) > 0:
                    print("Message sent!")
                else:
                    print("Error.")
                    print(rsp)
        elif option == 2:
            print("Check your new messages...")
            rsp = self.client.new(self.server_id)
            messages = rsp["result"]
            print("You have %d messages to read" % len(messages))
            if len(messages) != 0:
                next_option = input("Do you want to read all messages? ")
                if next_option.lower() == "y":
                    for message in messages:
                        message_rcv = self.client.recv(self.server_id, message, self.private_key)

                        # generate receipt for the received message
                        # the signature of the message received and then encrypted with the peer public key
                        # for that we need the peer public key

                        self.client.receipt(self.server_id, message_rcv["result"][0], message, message_rcv["result"][1].encode())

                        print("#####")
                        print("Message from ID: %s" % message_rcv["result"][0])
                        print("Content: %s" % message_rcv["result"][1].split("\t\tUUID\n\n")[0])
                        print("#####")
        elif option == 3:
            print("Peers you may send a message:\n")
            result = self.client.list()

            for peer in result["result"]:
                print("Peer id: " + str(peer["uuid"]))
        elif option == 4:
            sent_messages = self.client.all(self.server_id)["result"][1]

            if len(sent_messages) > 0:
                print("Select which message do you want to see the receipt: ")

                for i in range(0, len(sent_messages)):
                    print("%d - %s" % (i, sent_messages[i]))

                msg_id = int(input("Type: "))

                if 0 <= msg_id < len(sent_messages):
                    msg_id = sent_messages[msg_id]
                    status = self.client.status(self.server_id, msg_id, self.private_key)

                    print("Message: %s" % status["result"]["msg"]["message"].split("\t\tUUID\n\n")[0])
                    print("Receipt: %s" % ("YES" if len(status["result"]["receipts"]) > 0 else "NO"))
            else:
                print("There is no receipt yet.")
        else:
            return False

        print("-------------------------")
        return True


if __name__ == '__main__':
    chat = Client()
