import socket
import json
from client_cipher import ClientCipher


MSGLEN = 64 * 1024
TERMINATOR = "\r\n"


class ClientSocket:
    def __init__(self, host='127.0.0.1', port=8080):
        """
        Create a client to connect to server socket.
        :param host: server IP
        :param port: server port
        """
        # init client cipher
        self.client_cipher = ClientCipher()

        # try to connect with server
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))

        # init bootstrap
        self.channel_bootstrap()

    def channel_bootstrap(self):
        # phase 1
        result = self.client_cipher.negotiate_session_key(phase=1)

        # send to the server
        msg = {"type": "session_key", "msg": result}
        self.sck_send(msg, cipher=False)

        # wait for response
        response = self.sck_receive()

        # phase 3
        result = self.client_cipher.negotiate_session_key(phase=response["result"]["phase"], val=response["result"])
        msg = {"type": "session_key", "msg": result}
        self.sck_send(msg, cipher=False)

        # wait for response
        response = self.sck_receive()

    def sck_send(self, msg, cipher=True):
        """
        https://docs.python.org/2/howto/sockets.html
        :param msg: message to send
        :return: None
        """
        msg = json.dumps(msg)

        if cipher and self.client_cipher.session_key is not None:
            msg = self.client_cipher.secure_layer_encrypt(msg).decode()

        msg = (msg + TERMINATOR).encode()

        self.sock.sendall(msg)

    def sck_receive(self):
        """
        https://docs.python.org/2/howto/sockets.html
        :return: received piece of message
        """
        chunks = []

        while True:
            chunk = self.sock.recv(MSGLEN)

            if not chunk:
                break

            chunks.append(chunk.decode())

            if TERMINATOR in chunk.decode():
                break

        chunks = ''.join(''.join(chunks).split(TERMINATOR)[:-1])

        try:
            raw_data = json.loads(chunks)
        except json.JSONDecodeError:
            raw_data = json.loads(self.client_cipher.secure_layer_decrypt(chunks.encode()))

        return raw_data
