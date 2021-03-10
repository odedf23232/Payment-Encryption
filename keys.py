import sys
from random import randint, choices
import string

import argparse
from typing import Tuple

from consts import SCHNORR_Q, SCHNORR_G


def make_schnorr_keys(q: int, g: int) -> Tuple[int, int]:
    # the private key can just be some random number.
    # we can modify the range in here, but the bigger, the better.
    secret = randint(1000, 100000)

    # create the public key. its calculated as public = g^private mode q
    public_key = pow(g, secret, q)

    return secret, public_key


def make_blowfish_key() -> str:
    # the private key is a random string between 8 and 56 characters long (inclusive).
    size = randint(8, 56)
    secret = ''.join(choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=size))

    return secret


def main():
    """
    Main for creating schnorr/blowfish keys.
    It can generate both private and public keys.

    If --secret is used, it should contain the private key. This will cause
    the program to generate a public key matching that private key.

    If --secret is not used, a private key is generate as well as a public key
    matching it.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('--schnorr', action='store_true')
    parser.add_argument('--blowfish', action='store_true')

    args = parser.parse_args(sys.argv[1:])

    if args.schnorr:
        print('Schnorr')
        secret, public = make_schnorr_keys(SCHNORR_Q, SCHNORR_G)
        secret = randint(1000, 100000)
        print('Secret key', secret)
        print('Public key', public)
    elif args.blowfish:
        print('Blowfish')
        secret = make_blowfish_key()
        print('Secret key', secret)


if __name__ == '__main__':
    main()
