import socket
import json

MSGLEN = 64 * 1024
TERMINATOR = "\r\n"


class ClientSocket:
    def __init__(self, host='127.0.0.1', port=8080):
        """
        Create a client to connect to server socket.
        :param host: server IP
        :param port: server port
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))

    def sck_send(self, msg):
        """
        https://docs.python.org/2/howto/sockets.html
        :param msg: message to send
        :return: None
        """
        msg = (json.dumps(msg) + TERMINATOR).encode()
        self.sock.sendall(msg)

    def sck_receive(self):
        """
        https://docs.python.org/2/howto/sockets.html
        :return: received piece of message
        """
        chunks = []
        bytes_recd = 0

        while bytes_recd < MSGLEN:
            chunk = self.sock.recv(min(MSGLEN - bytes_recd, 2048))
            chunks.append(chunk.decode())

            if TERMINATOR in chunk.decode():
                return json.loads(''.join(chunks))

            bytes_recd = bytes_recd + len(chunk)



