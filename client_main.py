import json

from client import Client
from consts import SERVER_ADDRESS, SERVER_PORT, ENCODING, SCHNORR_G, SCHNORR_Q, CONFIRMATION_DATA, \
    DISABLE_ENCRYPTION, CLIENT_SECRETS_FILE
from crypto.encryption import create_encryption


def main():
    """
    Runs a client program, connecting to the server and sending
    data to it.
    """

    # load the secrets (i.e. keys) from the file so we can use them here.
    with CLIENT_SECRETS_FILE.open(mode='r') as f:
        secrets = json.load(f)

    encryption = create_encryption(secrets, ENCODING, SCHNORR_Q, SCHNORR_G, DISABLE_ENCRYPTION)

    # Open the client connection to the server in a context manager.
    # Connection will be closed when we exit the context.
    with Client(SERVER_ADDRESS, SERVER_PORT, encryption) as client:
        # Receive conformation from the server. If the message
        # passes the encryption verification then we know its the server
        # and everything is okay.
        # We'll also verify the contents of that data. This won't help much,
        # but we can use it to fix versioning.
        confirmation = client.receive(1024)
        if confirmation != CONFIRMATION_DATA:
            raise AssertionError('Wrong confirmation message')

        while True:
            user_data = input('(ctrl+c to exit)>')
            # Send data to the server.
            client.send(user_data)


if __name__ == '__main__':
    main()
