from client_socket import ClientSocket
import json
import base64
from client_cc import CitizenCard
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os
from datetime import datetime
import uuid


class ClientActions(ClientSocket):
    def __init__(self, cc, host='127.0.0.1', port=8080):
        """
        Create a client to connect to server socket.
        :param cc: Citizen Card user
        :param host: server IP
        :param port: server port
        """
        self.cc = cc
        super().__init__(host, port)

    def create(self, uuid, public_key_pem):
        """
        Create a message box for user in server.
        :param uuid: client uuid
        :param public_key_pem: the user public key PEM
        :return: the response of the server
        """
        msg = {"uuid": uuid,
               "cc_chain": self.cc.get_certificate_chain(),
               "cc_public_certificate": self.cc.get_certificate_pem().decode(),
               "user_public_pem": public_key_pem.decode()}

        data_signature = self.cc.sign(json.dumps(msg).encode())

        msg["type"] = "create"
        msg["signature"] = base64.b64encode(data_signature).decode()

        self.sck_send(msg)

        return self.sck_receive()

    def list(self, uuid=None):
        """
        Sent by the client in order to list users with messages box in the server.
        :param uuid: client uuid (optional)
        :return: the response of the server
        """
        msg = {"type": "list", "uuid": uuid}
        self.sck_send(msg)

        return self.sck_receive()

    def new(self, id):
        """
        Sent by the client in order to list all new messages in users' message box.
        :param id: client uuid
        :return: the response of the server
        """
        msg = {"type": "new", "id": id}
        self.sck_send(msg)

        return self.sck_receive()

    def all(self, uuid):
        """
        Sent by the client in order to list all messages in users' message box.
        :param uuid: client uuid
        :return: the response of the server
        """
        msg = {"type": "all", "id": uuid}
        self.sck_send(msg)

        return self.sck_receive()

    def send(self, source_uuid, destination_uuid, msg, public_key):
        """
        Sent by the client to send a message to other client's message box.
        :param destination_uuid
        :param source_uuid
        :param msg
        :param public_key: user public key
        :return: the response of the server
        """
        peer_public_details = self.get_user_public_details(destination_uuid)
        peer_public_key = serialization.load_pem_public_key(peer_public_details["user_public_pem"].encode(),
                                                            backend=default_backend())

        # sign the message with the CC, but only the message
        msg = msg + "\t\tUUID\n\n" + str(uuid.uuid4())  # unique value to the msg append

        msg = json.dumps({
            "message": msg,
            "signature": base64.b64encode(self.cc.sign(msg.encode())).decode()
        })

        # only the destination user can see the message
        dst_msg = self.client_cipher.hybrid_cipher(msg.encode(), peer_public_key, self.client_cc.get_mode()).decode()

        # only the user that sent (receipts box) can see the message
        copy_msg = self.client_cipher.hybrid_cipher(msg.encode(), public_key, self.client_cc.get_mode()).decode()

        msg = {"type": "send", "src": source_uuid, "dst": destination_uuid, "msg": dst_msg, "copy": copy_msg}

        self.sck_send(msg)

        return self.sck_receive()

    def recv(self, uuid, message_id, private_key):
        """
        Sent by the client in order to receive a message from a user's message box.
        :param message_id:
        :param uuid: client uuid
        :param private_key: user private key
        :return: the response of the server
        """
        msg = {"type": "recv", "id": uuid, "msg": message_id}
        self.sck_send(msg)

        messages = self.sck_receive()

        if len(messages["result"]) == 2:
            # try to decode messages, 0 message_id and 1 the message
            messages["result"][1] = json.loads(self.client_cipher.hybrid_decipher(messages["result"][1].encode(),
                                                                                  private_key).decode())

            # verify signature
            peer_public_details = self.get_user_public_details(int(messages["result"][0]))

            CitizenCard.verify(messages["result"][1]["message"].encode(),
                               base64.b64decode(messages["result"][1]["signature"]),
                               peer_public_details["cc_public_certificate"].encode())

            messages["result"][1] = messages["result"][1]["message"]

        return messages

    def receipt(self, uuid_msg_box, uuid_from_id, message_id, msg_content):
        """
        Sent by the client after receiving and validating a message from a message box.
        :param uuid_msg_box (receiver)
        :param uuid_from_id (sender) to use in user public details to sign
        :param message_id
        :param msg_content
        :return: None
        """
        # generate receipt for the received message
        # the signature of the message received and then encrypted with the peer public key
        peer_public_details = self.get_user_public_details(int(uuid_from_id))
        peer_public_key = serialization.load_pem_public_key(peer_public_details["user_public_pem"].encode(),
                                                            backend=default_backend())

        time_now = str(datetime.now().timestamp() * 1000)
        signature = self.cc.sign(msg_content + time_now.encode())
        signature = base64.b64encode(self.client_cipher.hybrid_cipher(signature, peer_public_key, self.client_cc.get_mode(), self.client_cc.get_mode())).decode()

        msg = {"type": "receipt", "id": uuid_msg_box, "msg": message_id, "receipt": signature + "\t\ntimestamp\t\n" + time_now}
        self.sck_send(msg)

    def status(self, uuid_msg_box, message_id, private_key):
        """
        Sent by the client for checking the reception status of a sent message.
        :param uuid_msg_box
        :param message_id
        :param private_key: user private key
        :return: None
        """
        msg = {"type": "status", "id": uuid_msg_box, "msg": message_id}

        self.sck_send(msg)

        status = self.sck_receive()

        status["result"]["msg"] = json.loads(self.client_cipher.hybrid_decipher(status["result"]["msg"].encode(),
                                                                                private_key))

        CitizenCard.verify(status["result"]["msg"]["message"].encode(),
                           base64.b64decode(status["result"]["msg"]["signature"]),
                           self.cc.get_certificate_pem())

        for receipt in status["result"]["receipts"]:
            timestamp = receipt["receipt"].split("\t\ntimestamp\t\n")[1]
            receipt["receipt"] = receipt["receipt"].split("\t\ntimestamp\t\n")[0]

            signature = self.client_cipher.hybrid_decipher(base64.b64decode(receipt["receipt"]), private_key)
            peer_public_details = self.get_user_public_details(int(receipt["id"]))

            print("Receipt by user %s" % receipt["id"])
            print("User signed receipt at: %s" % datetime.fromtimestamp(float(timestamp)/1000).strftime('%Y-%m-%d %H:%M:%S'))
            print("Server received receipt at: %s" % datetime.fromtimestamp(float(receipt["date"])/1000).strftime('%Y-%m-%d %H:%M:%S'))
            print("")

            CitizenCard.verify(status["result"]["msg"]["message"].encode()+timestamp.encode(),
                               signature,
                               peer_public_details["cc_public_certificate"].encode())

        return status

    def get_user_public_details(self, user_id):
        msg = {"type": "user_public_details", "id": user_id}
        self.sck_send(msg)

        peer_public_details = self.sck_receive()["result"]
        signature = peer_public_details["signature"]
        del peer_public_details["signature"]

        # validate received certificate
        CitizenCard.validate_chain(chain=peer_public_details["cc_chain"], pem_certificate=peer_public_details["cc_public_certificate"].encode())

        # verify received public keys with the public cc key from the certificate
        CitizenCard.verify(json.dumps(peer_public_details).encode(), base64.b64decode(signature.encode()),
                           peer_public_details["cc_public_certificate"].encode())

        return peer_public_details

    def get_server_id(self, uuid):
        msg = {"type": "exists", "uuid": uuid}
        self.sck_send(msg)

        return self.sck_receive()
