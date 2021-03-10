from pathlib import Path

SERVER_ADDRESS = ''
SERVER_PORT = 50005

ENCODING = 'utf-8'

SCHNORR_G = 2
SCHNORR_Q = 2695139

DATA_FOLDER = Path('data')

CONFIRMATION_DATA = 'The paranoia is in bloom'

DISABLE_ENCRYPTION = False

CLIENT_SECRETS_FILE = DATA_FOLDER / 'client_secrets.json'
SERVER_SECRETS_FILE = DATA_FOLDER / 'server_secrets.json'
