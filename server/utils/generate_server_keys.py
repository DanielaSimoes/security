from utils import generate_keys


if __name__ == '__main__':
    server_keys = generate_keys()

    private_file = 'server_private_key.pem'
    f = open(private_file, 'wb')
    f.write(server_keys.exportKey())
    f.close()

    public_file = 'server_public_key.pem'
    f = open(public_file, 'wb')
    f.write(server_keys.publickey().exportKey())
    f.close()
