from client_socket import ClientSocket


class ClientActions(ClientSocket):
    def __init__(self, host='127.0.0.1', port=8080):
        """
        Create a client to connect to server socket.
        :param host: server IP
        :param port: server port
        """
        super().__init__(host, port)

    def create(self, uuid):
        """
        Create a message box for user in server.
        :param uuid: client uuid
        :return: the response of the server
        """
        msg = {"type": "create", "uuid": uuid}
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

    def send(self, source_uuid, destination_uuid, msg):
        """
        Sent by the client to send a message to other client's message box.
        :param destination_uuid
        :param source_uuid
        :param msg
        :return: the response of the server
        """
        msg = {"type": "send", "src": source_uuid, "dst": destination_uuid, "msg": msg, "copy": msg}
        self.sck_send(msg)

        return self.sck_receive()

    def recv(self, uuid, message_id):
        """
        Sent by the client in order to receive a message from a user's message box.
        :param message_id:
        :param uuid: client uuid
        :return: the response of the server
        """
        msg = {"type": "recv", "id": uuid, "msg": message_id}
        self.sck_send(msg)

        return self.sck_receive()

    def receipt(self, uuid_msg_box, message_id, signature):
        """
        Sent by the client after receiving and validating a message from a message box.
        :param uuid_msg_box
        :param message_id
        :param signature
        :return: None
        """
        msg = {"type": "receipt", "id": uuid_msg_box, "msg": message_id, "receipt": signature}
        self.sck_send(msg)

    def status(self, uuid_msg_box, message_id):
        """
        Sent by the client for checking the reception status of a sent message.
        :param uuid_msg_box
        :param message_id
        :return: None
        """
        msg = {"type": "status", "id": uuid_msg_box, "msg": message_id}
        self.sck_send(msg)

        return self.sck_receive()

    def get_server_id(self, uuid):
        msg = {"type": "exists", "uuid": uuid}
        self.sck_send(msg)

        return self.sck_receive()
