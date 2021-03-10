from typing import Callable, Dict

from .blowfish import Blowfish
from .cipher import Cipher
from .schnorr import SchnorrSigner, SchnorrVerifier, sha256_hash, SchnorrSignature
from .signature import Signer, Verifier, Signature

import struct


class Encryption(object):
    """
    Implements the full encryption protocol used by our
    application.

    The encryption has two parts:
        - data is encrypted with a cipher
        - data is signed with a signature
    """
    _MESSAGE_FORMAT = '>ii'

    def __init__(self, encoding: str, cipher: Cipher,
                 signer: Signer, verifier: Verifier,
                 signature: Callable[[bytes], Signature],
                 disabled: bool = False):
        self._encoding = encoding
        self._cipher = cipher
        self._signer = signer
        self._verifier = verifier
        self._signature = signature
        self._disabled = disabled

    def encrypt(self, data: str) -> bytes:
        """
        Encrypts the raw data.

        - We first sign the raw data, which will be used to verify the source (us)
          and that the contents are unchanged.
        - Then we encrypt the data with a cipher
        - The encrypted data and signature are serialized into binary data so
          we can send it.

        :param data: raw data to encrypt.
        :return: encrypted data.
        """
        if self._disabled:
            return data.encode(self._encoding)

        # We first sign on the raw data, to provide confirmation of it.
        # then we encrypt the data to hide it.
        signature = self._signer.sign(data)
        data, padding_size = self._cipher.encrypt(data)

        # encode the data into bytes
        # and pack the signature into bytes.
        data = data.encode(self._encoding)
        signature = signature.pack()

        # construct the message header. It is made up of information on sizes
        # that will allow us to parse the message
        sizes = struct.pack(self._MESSAGE_FORMAT, len(data), padding_size)

        # combine all the data bytes of the message
        return sizes + data + signature

    def decrypt(self, data: bytes) -> str:
        """
        Decrypts the encrypted data.

        - We first deserialize the data and signature.
        - Then we decrypt the data with a cipher
        - Then we verify the signature on the data.

        :param data: encrypted data.
        :return: encrypted data.
        """
        if self._disabled:
            return data.decode(self._encoding)

        # find the size of the header
        # and split the data into header and contents
        format_size = struct.calcsize(self._MESSAGE_FORMAT)
        sizes, data = data[:format_size], data[format_size:]

        # unpack the header information
        # and use it to divide the bytes into data and signature parts
        len_data, padding_size = struct.unpack(self._MESSAGE_FORMAT, sizes)
        data, signature = data[:len_data], data[len_data:]

        # now we do the exact backwards of the encryption:
        # decode data from bytes into encrypted data, and
        # unpack the signature from bytes
        data = data.decode(self._encoding)
        signature = self._signature(signature)

        # decrypt the data, taking into account the padding
        # we might have added because of blocks
        data = self._cipher.decrypt(data, padding_size)

        # verify the signature on the decrypted data.
        if not self._verifier.verify(data, signature):
            raise ValueError('signature not verified')

        return data


def create_encryption(secrets: Dict, encoding: str,
                      scnorr_q: int, schnorr_g: int, disabled: bool = False) -> Encryption:
    # Create the encryption protocol:
    # - we use Blowfish cipher to hide/protect the data
    # - we use Schnorr to sign and verify authenticity of messages and their sources.
    #   - We have a list of accepted public keys, each is a different source the we are
    #   okay talking with.
    cipher = Blowfish(key=secrets['blowfish']['secret'])
    signer = SchnorrSigner(key=secrets['schnorr']['secret'], q=scnorr_q,
                           g=schnorr_g, hash_func=sha256_hash)
    verifier = SchnorrVerifier(keys=secrets['schnorr']['accepted_public'], q=scnorr_q,
                               g=schnorr_g, hash_func=sha256_hash)
    encryption = Encryption(encoding, cipher, signer, verifier, SchnorrSignature, disabled=disabled)

    return encryption
