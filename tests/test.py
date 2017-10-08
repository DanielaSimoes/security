# coding=utf-8
import logging
import os
import sys
import unittest

sys.path.insert(1, os.path.join(sys.path[0], '../client'))

# noinspection PyUnresolvedReferences
from client_actions import ClientActions
# noinspection PyUnresolvedReferences
from client_socket import ClientSocket


class ServerRestart(ClientSocket):
    def __init__(self, host='127.0.0.1', port=8080):
        """
        Create a client to connect to server socket.
        :param host: server IP
        :param port: server port
        """
        super().__init__(host, port)

    def restart(self):
        msg = {"type": "delete_all"}
        self.sck_send(msg)


class UnitTests(unittest.TestCase):

    @classmethod
    def setUpClass(self):
        print("OK")
        self.client = ClientActions()
        """
        ONLY FOR DEV
        """
        server = ServerRestart()
        server.restart()

    def tearDown(self):
        pass

    def test_all(self):
        """
        Monolithic sequential test
        :return:
        """

        """
        TEST CREATE
        """
        rsp = self.client.create(10)
        self.assertTrue('result' in rsp)
        self.assertTrue(type(rsp['result']) is int)
        self.id1 = rsp["result"]

        rsp = self.client.create(20)
        self.assertTrue('result' in rsp)
        self.assertTrue(type(rsp['result']) is int)
        self.id2 = rsp["result"]

        """
        TEST LIST
        """
        rsp = self.client.list()
        self.assertEqual(rsp, {'result': [{'uuid': 10}, {'uuid': 20}]})

        """
        TEST NEW
        with no messages
        """
        rsp = self.client.new(self.id1)
        self.assertEqual(rsp, {'result': []})

        """
        TEST ALL messages by uuid
        with no messages
        """
        rsp = self.client.all(self.id1)
        self.assertEqual(rsp, {'result': [[], []]})

        """
        TEST send message
        """
        rsp = self.client.send(self.id1, self.id2, "Testeee")
        self.assertEqual(rsp, {'result': ['1_1', '2_1']})
        self.message_sent_id = rsp["result"][0]
        self.receipt_id = rsp["result"][1]

        """
        TEST NEW
        with messages to read
        """
        rsp = self.client.new(self.id2)
        self.assertEqual(rsp, {'result': [self.message_sent_id]})

        """
        TEST RECV
        """
        rsp = self.client.recv(self.id2, self.message_sent_id)
        self.assertEqual(rsp, {'result': ['1', 'Testeee']})

        """
        TEST RECEIPT
        """
        rsp = self.client.receipt(self.id2, self.message_sent_id, "signature")
        self.assertEqual(rsp, None)

        """
        TEST STATUS
        """
        rsp = self.client.status(self.id1, self.receipt_id)
        del rsp["result"]["receipts"][0]["date"]
        self.assertEqual(rsp, {'result': {'msg': 'Testeee', 'receipts': [{'id': '2', 'receipt': 'signature'}]}})

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr)
    logging.getLogger().setLevel(logging.DEBUG)
