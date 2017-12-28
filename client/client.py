from client_actions import ClientActions


class Client:
    def __init__(self):
        client = ClientActions()

        account_created = input("Do you already have an account? (y/n)")

        while account_created != "y" and account_created != "n":
            account_created = input("Do you already have an account? (y/n)")

        if account_created == "n":
            user_id = int(input("Choose a ID:"))
            created = False
            rsp = client.create(user_id)

            if "result" in rsp:
                server_id = rsp["result"]
                created = True

            while not created:
                if rsp == {'error': 'uuid already exists'}:
                    user_id = int(input("Choose other ID please:"))
                    rsp = client.create(user_id)
                else:
                    created = True
        else:
            user_id = int(input("Insert your ID:"))
            server_id = client.get_server_id(user_id)["result"]

        print("Peers you may send a message:\n")
        for peer in client.list()["result"]:
            print("Peer id: " + str(peer["uuid"]))

        options = str(input("Send a message: m \nVerify new messages: v \n"))

        if options == "m":
            peer_to_connect = int(input("Write the number of the peer you want to send a message:"))
            server_id_peer = client.get_server_id(peer_to_connect)["result"]
            print("OK")
            message = str(input("Write your message:"))
            rsp = client.send(server_id, server_id_peer, message)
            print(rsp)
        elif options == "v":
            print("Check your messages...")
            rsp = client.all(server_id)
            messages = rsp["result"]


if __name__ == '__main__':
    chat = Client()