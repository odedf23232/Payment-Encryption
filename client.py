import socket

from crypto.encryption import Encryption


class Client(object):
    """
    Provides secure TCP communication with a server end-point.
    """

    def __init__(self, server_address: str, server_port: int, encryption: Encryption):
        """
        Creates a new client instance, connecting to the wanted server.
        :param server_address: address to the server to connect to. Either ip address or hostname. 
        :param server_port: port the server is listening to.
        :param encryption: encryption protocol for secure messaging.
        """
        # creates a TCP socket.
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._encryption = encryption

        # connect the socket to the server address and port.
        self._socket.connect((server_address, server_port))

    def send(self, data: str):
        """
        Sends a string data to the remote. Data is encrypted and signed to
        secure it, as defined by the encryption implementation provided in the
        constructor.

        :param data: data to send
        """
        # encrypt the data and send it.
        data = self._encryption.encrypt(data)
        self._socket.send(data)

    def receive(self, max_size: int) -> str:
        """
        Reads data sent from the remote. The data is decrypted and verified
        as defined by the encryption implementation provided in the constructor.
        If no data was sent from the remote, this call blocks until data is received.

        :param max_size: maximum amount of data to receive
        :return: raw data from the remote
        :raise AssertionError: if data received could not be verified as genuine from the remote.
        """
        # receive data from the socket. blocking until data is available.
        # data is decrypted and verified.
        data = self._socket.recv(max_size)
        return self._encryption.decrypt(data)

    def close(self):
        """
        Closes the socket.
        """
        self._socket.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return self
