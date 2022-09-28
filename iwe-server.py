#!/usr/bin/python3
import base64
import gzip
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
# AES 256 encryption/decryption using pycrypto library
# AES 256 encryption/decryption using pycrypto library

import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import unpad


def aes256_decrypt(aes_b64_enc: str, password: str) -> bytes:
    """
    Takes an encrypted, gzipped base64 string and converts it into a byte array.

    The base64 string is packed the following way:
    decrypt base64 > decompress gzip > AES Hex bytes
    The first 16 bytes of the AES hex is the AES IV.
    The password is SHA256 hashed to get a 32 byte long password

    :param aes_b64_enc: base64 sring to decrypt
    :param password: string plain text password to decrypt AES with
    :return: returns a byte object ob the decrypted file
    """

    # SHA256 hash the plain text password
    key_sha256 = hashlib.sha256(password.encode()).digest()
    # decode the base64 string
    b64_decoded = base64.b64decode(aes_b64_enc)
    # decompress gzip bytes
    gzip_decoded = gzip.decompress(b64_decoded)
    # extract the AES IV from the cipher text
    aes_iv = gzip_decoded[:16]
    aes_cipher_text = gzip_decoded[16:]

    try:
        cipher = AES.new(key_sha256, AES.MODE_CBC, aes_iv)
        plain_text = unpad(cipher.decrypt(aes_cipher_text), AES.block_size)

    except (ValueError, KeyError) as e:
        print("ERROR: Incorrect decryption")
        return bytes('0')

    return plain_text


b64_enc = "H4sIAAAAAAAACgFgBJ/7/HuObfA31PbN5WFaZhoBnad+MD71nwEmbukraSS9g9OblOssPYWERoMoJtDD50xcy7E2t6IXyqnW2lU568cLy45EXZDGddgaH21DMcOwtst1lddDOEBK5Vpr5kZ4crW83XX7sI/p+GdgDUIemu9TDq3rS9j11tWw1WUWbXb5reEx3IfvABzZKOkRFNhk7pKdsPqshjfxdeWcoTPETYr6MfzgS1Z6MbY+T/XBI422K3ivl1HHvnszvd2rL4B5wh1pXsLm2ojUH3oao5QAN4v5PI7buVUnVWInaX9KnwoLMsR2rSy3/61Wv72Fd5MksfUxtLPKbxae2PJpd/SpK99OZq1Xdr/iEHUbCaGcqbLt4llmgcbjMlzLi0nNY9JPqdH4+XqvBv+AyYrjU0R039DllBrv1FwV4ZTJ/S4wBuvMzAhtecZ8aRMQtfwxSW0uxbqSqLny5rMfafR2uz/dZuFPpPxP9IWQC2pUgzvI++w7Bu6FqHd0Uh3YBDCKyu1bh+SlsKOGEI6qqOqBYLekx3vmqXM/3T1NZqNSO74oX765dga331Jw7NYgJwqn6BjKDR/7NDbVLv/flScUdwNi+Q8KFIxmNRnSMvOgsyrG/guJ/rNpqhzUH2r4q6khJmVzIPIM5Bpu54M9GNTeWFXGQx8Wpb9RiwQx/alfmff8k24fQPTxp3PMtKSDskPGnH2NpEVrvR6mZHsPjQLrpdY8eL59lx5yz+l+QWaumWAYG54/jZoQNsh2C4APQjmbAEqzo+G4e66n2uPqgBEPTLZExmBfyg6nxeWYdMwxGy/CIJzd6UuxKRYvdO5N1ZIXsyD/idKr5kLnZlOL0tY/v/xSJYp3dnnZ+cywSSKmFs2qNNvXUps/Ary38NtRBvZjfWO9RakOvx9FUCpVB6sq+etA8TxVTaEvd3NrFfMiicDex175m3mrWkIY7AGIENONg1xMs4xooOsnkS7Tbm9S2Y/dffHQLQp6B16MgHUIFZ5iIUK+6Wr4XtqMeX2hVdHAYaJbQL7oSB8sL80f/MN4d/54SV27semC1j0cafZYyWkm6gL5VOJ+epo+4vcyR/ElqOWsiBBHqsKTVkothz3GZN2E1CwKbq4LeV3nqMjPiSH/8vWkj7Ooy7o/1EicV9wlZ2pc942roTF1GPKmEg/RaksrmYAG6/EIll5evlKUqyrb9EpX3CKqXyt+640oDCzc4tML2aPEqa9jJ5f3Nd7upfveA67vV6uKkUN64HDii1eEY+PUyNfmILYPzMJEa6peuzXqV5dxaEbkewI5sSj0CwfaCZYmogZQWPKTSrQBt+68yXXQVJeLPmZycgKP+Eo1OIcTlqhQ6RrB91uqaHfxe/nJNz6pviWs+rbbSj6k8mllViR7vUGx48frrQwzKWUXY/L0TA4t0+GAGEPSY2NOYcHWNbfB2ULNtIvKj6ZpC3fu3sgAbhVAZEopsAHHIRfF4KDl9bjPTeMKttlqDUV351ZwaI2t03BDXP1gBAAA"
pw = "password"


pain = aes256_decrypt(b64_enc, pw)

print(pain.decode())

