from typing import Dict

from keys import make_schnorr_keys, make_blowfish_key
from consts import ENCODING, SCHNORR_Q, SCHNORR_G, DISABLE_ENCRYPTION
from crypto.encryption import Encryption, create_encryption


def make_client_side(secrets: Dict) -> Encryption:
    print('Client secrets', secrets)
    return create_encryption(secrets, ENCODING, SCHNORR_Q, SCHNORR_G, DISABLE_ENCRYPTION)


def make_server_side(secrets: Dict) -> Encryption:
    print('Server secrets', secrets)
    return create_encryption(secrets, ENCODING, SCHNORR_Q, SCHNORR_G, DISABLE_ENCRYPTION)


RAW_DATA = 'Its the final countdown'


def main():
    # make secrets
    server_schnorr_secret, server_schnorr_public = make_schnorr_keys(SCHNORR_Q, SCHNORR_G)
    client_schnorr_secret, client_schnorr_public = make_schnorr_keys(SCHNORR_Q, SCHNORR_G)
    blowfish_secret = make_blowfish_key()

    # make both sides of the encryption
    client = make_client_side({
        "blowfish": {
            "secret": blowfish_secret
        },
        "schnorr": {
            "secret": client_schnorr_secret,
            "accepted_public": [
                server_schnorr_public
            ]
        }
    })
    server = make_server_side({
        "blowfish": {
            "secret": blowfish_secret
        },
        "schnorr": {
            "secret": server_schnorr_secret,
            "accepted_public": [
                client_schnorr_public
            ]
        }
    })

    # encrypt data
    encrypted = client.encrypt(RAW_DATA)

    # modify the data somehow. Doing this should invalidate the signature
    encrypted = encrypted.capitalize()

    # try to decrypt. if the data was touched in anyway this should fail due to signature validation
    # (or maybe cipher decryption at some instances).
    decrypted = server.decrypt(encrypted)

    assert decrypted == RAW_DATA


if __name__ == '__main__':
    main()
