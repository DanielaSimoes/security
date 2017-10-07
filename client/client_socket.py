import socket

MSGLEN = 64 * 1024


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
        totalsent = 0
        while totalsent < MSGLEN:
            sent = self.sock.send(msg[totalsent:])
            if sent == 0:
                raise RuntimeError("socket connection broken")
            totalsent = totalsent + sent

    def sck_receive(self):
        """
        https://docs.python.org/2/howto/sockets.html
        :return: received piece of message
        """
        chunks = []
        bytes_recd = 0
        while bytes_recd < MSGLEN:
            chunk = self.sock.recv(min(MSGLEN - bytes_recd, 2048))
            if chunk == '':
                raise RuntimeError("socket connection broken")
            chunks.append(chunk)
            bytes_recd = bytes_recd + len(chunk)
        return ''.join(chunks)


