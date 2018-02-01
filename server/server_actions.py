from server_registry import *
from server_cipher import ServerCipher
import shutil
import base64


class ServerActions:
    def __init__(self):
        self.messageTypes = {
            'all': self.processAll,
            'list': self.processList,
            'new': self.processNew,
            'send': self.processSend,
            'recv': self.processRecv,
            'create': self.processCreate,
            'receipt': self.processReceipt,
            'status': self.processStatus,
            'exists': self.processExists,
            'user_public_details': self.processUserPublicDetails,
            'session_key': self.processSessionKey
        }

        self.me = None  # represents user obj

        self.server_cipher = ServerCipher()
        self.registry = ServerRegistry()

    def handleRequest(self, s, request, client):
        """Handle a request from a client socket.
        """
        try:
            sec_data = None

            if client.server_cipher.session_key is not None:
                request, sec_data = client.server_cipher.secure_layer_decrypt(request.encode())

            logging.info("HANDLING message from %s: %r" %
                         (client, repr(request)))

            try:
                req = json.loads(request)
            except:
                logging.exception("Invalid message from client")
                return

            if not isinstance(req, dict):
                log(logging.ERROR, "Invalid message format from client")
                return

            if 'type' not in req:
                log(logging.ERROR, "Message has no TYPE field")
                return

            if req['type'] in self.messageTypes:
                self.messageTypes[req['type']](req, client, sec_data)
            else:
                log(logging.ERROR, "Invalid message type: " +
                    str(req['type']) + " Should be one of: " + str(self.messageTypes.keys()))
                client.sendResult({"error": "unknown request"}, sec_data)

        except Exception as e:
            logging.exception("Could not handle request")

    def processSessionKey(self, data, client, sec_data):
        if "phase" not in data["msg"] or not isinstance(data["msg"]["phase"], int):
            log(logging.ERROR, "The process session key must have a phase number.")
            client.sendResult({"error": "unknown request"}, sec_data)
            return

        if data["msg"]["phase"] == 2 or data["msg"]["phase"] == 4:
            result = client.server_cipher.negotiate_session_key(data["msg"]["phase"], data["msg"])
            # we have the shared secret but the client don't, so force no cipher response
            client.sendResult({"result": result}, sec_data)
            return
        else:
            log(logging.ERROR, "Invalid message phase: " + str(data["msg"]['phase']))
            client.sendResult({"error": "unknown request"}, sec_data)
            return

    def processExists(self, data, client, sec_data):
        if self.registry.userExists_uuid(data["uuid"]):
            for i in range(1, len(self.registry.users) + 1):
                if self.registry.users[i]["description"]["uuid"] == data["uuid"]:
                    client.sendResult({"result": self.registry.users[i]["id"]}, sec_data)
                    return
        client.sendResult({"result": None}, sec_data)

    def processUserPublicDetails(self, data, client, sec_data):
        for i in range(1, len(self.registry.users) + 1):
            if self.registry.users[i]["id"] == data["id"]:
                client.sendResult({"result": self.registry.users[i]["description"]}, sec_data)
                return
        client.sendResult({"result": None})

    def processCreate(self, data, client, sec_data):
        """
        Create a message box for the user in server.
        :param data: dic with type, uuid, ...
        :param client: client socket
        :param sec_data: security related data needed to build the response
        :return: send result to client socket
        """
        log(logging.DEBUG, "%s" % json.dumps(data))

        if 'uuid' not in data.keys():
            log(logging.ERROR, "No \"uuid\" field in \"create\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"}, sec_data)
            return

        uuid = data['uuid']
        if not isinstance(uuid, str):
            log(logging.ERROR, "No valid \"uuid\" field in \"create\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"}, sec_data)
            return

        signature = data["signature"]
        del data["type"]
        del data["signature"]

        # validate received certificate
        self.server_cipher.cc.validate_chain(chain=data["cc_chain"], pem_certificate=data["cc_public_certificate"].encode())

        # verify received public keys with the public cc key from the certificate
        self.server_cipher.cc.verify(json.dumps(data).encode(), base64.b64decode(signature.encode()),
                                     data["cc_public_certificate"].encode())

        if self.registry.userExists_uuid(uuid):
            self.me = self.registry.getUser(uuid)
            log(logging.ERROR, "User already exists: " + json.dumps(data))
            client.sendResult({"error": "uuid already exists"}, sec_data)
            return

        data["signature"] = signature

        self.me = self.registry.addUser(data)
        client.sendResult({"result": self.me.id}, sec_data)

    def processList(self, data, client, sec_data):
        """
        Sent by the client in order to list users with messages box in the server.
        :param data: dic with type, id (optional uuid), ...
        :param client: client socket
        :param sec_data: security related data needed to build the response
        :return: send result to client socket
        """
        log(logging.DEBUG, "%s" % json.dumps(data))

        user = 0  # 0 means all users
        userStr = "all users"
        if 'id' in data.keys():
            user = int(data['id'])
            userStr = "user%d" % user

        log(logging.DEBUG, "List %s" % userStr)

        userList = self.registry.listUsers(user)

        client.sendResult({"result": userList}, sec_data)

    def processNew(self, data, client, sec_data):
        """
        Sent by the client in order to list all new messages in users' message box.
        :param data: dic with type, id (uuid), ...
        :param client: client socket
        :param sec_data: security related data needed to build the response
        :return: send result (dic with a list with new messages) to client socket
        """
        log(logging.DEBUG, "%s" % json.dumps(data))

        user = -1
        if 'id' in data.keys():
            user = int(data['id'])

        if user < 0:
            log(logging.ERROR,
                "No valid \"id\" field in \"new\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong message format"}, sec_data)
            return

        if user != self.me.id:
            log(logging.ERROR,
                "Can't read messages from other user message box!")
            client.sendResult({"error": "Can't read messages from other user message box!"}, sec_data)
            return

        client.sendResult({"result": self.registry.userNewMessages(user)}, sec_data)

    def processAll(self, data, client, sec_data):
        """
        Sent by the client in order to list all messages in users' message box.
        :param data: dic with type, id (uuid), ...
        :param client: client socket
        :param sec_data: security related data needed to build the response
        :return: send result (dic with a list with received messages and other list with sent messages) to client socket
        """
        log(logging.DEBUG, "%s" % json.dumps(data))

        user = -1
        if 'id' in data.keys():
            user = int(data['id'])

        if user < 0:
            log(logging.ERROR,
                "No valid \"id\" field in \"new\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong message format"}, sec_data)
            return

        if user != self.me.id:
            log(logging.ERROR,
                "Can't read messages from other user message box!")
            client.sendResult({"error": "Can't read messages from other user message box!"}, sec_data)
            return

        client.sendResult({"result": [self.registry.userAllMessages(user), self.registry.userSentMessages(user)]},
                          sec_data)

    def processSend(self, data, client, sec_data):
        """
        Sent by the client to send a message to other client's message box.
        :param data: dic with type, src (uuid source), dst (uuid destination),
        msg (json or base64 encoded): encrypted and signed message to be delivered to the target message box,
        copy (json or base64 encoded): contains a copy of the message to be stored in the receipt box of the sender (encrypted)...
        :param client: client socket
        :param sec_data: security related data needed to build the response
        :return: send result (dic with a list with message id and receipt id) to client socket
        """
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set(data.keys()).issuperset(set({'src', 'dst', 'msg', 'msg'})):
            log(logging.ERROR,
                "Badly formated \"send\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong message format"}, sec_data)
            return

        srcId = int(data['src'])
        dstId = int(data['dst'])
        msg = str(data['msg'])
        copy = str(data['copy'])

        if not self.registry.userExists(srcId):
            log(logging.ERROR,
                "Unknown source id for \"send\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"}, sec_data)
            return

        if not self.registry.userExists(dstId):
            log(logging.ERROR,
                "Unknown destination id for \"send\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"}, sec_data)
            return

        # Save message and copy

        response = self.registry.sendMessage(srcId, dstId, msg, copy)

        client.sendResult({"result": response}, sec_data)

    def processRecv(self, data, client, sec_data):
        """
        Sent by the client in order to receive a message from a user's message box.
        :param data: dic with type, id (uuid), message id ...
        :param client: client socket
        :param sec_data: security related data needed to build the response
        :return: send result (dic with a list with source uuid and message (base64) to client socket)
        """
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"recv\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"}, sec_data)
            return

        fromId = int(data['id'])

        if fromId != self.me.id:
            log(logging.ERROR,
                "Can't read messages from other user message box!")
            client.sendResult({"error": "Can't read messages from other user message box!"}, sec_data)
            return

        msg = str(data['msg'])

        if not self.registry.userExists(fromId):
            log(logging.ERROR,
                "Unknown source id for \"recv\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"}, sec_data)
            return

        if not self.registry.messageExists(fromId, msg):
            log(logging.ERROR,
                "Unknown source msg for \"recv\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"}, sec_data)
            return

        # Read message

        response = self.registry.recvMessage(fromId, msg)

        client.sendResult({"result": response}, sec_data)

    def processReceipt(self, data, client, sec_data):
        """
        Sent by the client after receiving and validating a message from a message box.
        :param data: dic with type, id (uuid), msg (message id), receipt (signature over clear text message)...
        :param client: client socket
        :param sec_data: security related data needed to build the response
        :return: None
        """
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg', 'receipt'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"receipt\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong request format"}, sec_data)
            return

        fromId = int(data["id"])

        if fromId != self.me.id:
            log(logging.ERROR,
                "Can't read messages from other user message box!")
            client.sendResult({"error": "Can't read messages from other user message box!"}, sec_data)
            return

        msg = str(data['msg'])
        receipt = str(data['receipt'])

        if not self.registry.messageWasRed(str(fromId), msg):
            log(logging.ERROR, "Unknown, or not yet red, message for \"receipt\" request " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"}, sec_data)
            return

        self.registry.storeReceipt(fromId, msg, receipt)

    def processStatus(self, data, client, sec_data):
        """
        Sent by the client for checking the reception status of a sent message.
        :param data: dic with type, id (uuid), msg (message id)...
        :param client: client socket
        :param sec_data: security related data needed to build the response
        :return: reply with an object containing the sent message and a vector of receipt objects, each containing the
        receipt data (when it was received by the server) the id of receipt sender and the receipt itself.
        """
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"status\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"}, sec_data)
            return

        fromId = int(data['id'])

        if fromId != self.me.id:
            log(logging.ERROR,
                "Can't read messages from other user message box!")
            client.sendResult({"error": "Can't read messages from other user message box!"}, sec_data)
            return

        msg = str(data["msg"])

        if (not self.registry.copyExists(fromId, msg)):
            log(logging.ERROR, "Unknown message for \"status\" request: " + json.dumps(data))
            client.sendResult({"error", "wrong parameters"}, sec_data)
            return

        response = self.registry.getReceipts(fromId, msg)
        client.sendResult({"result": response}, sec_data)
