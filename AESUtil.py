from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from constants import BLOCK_SIZE


def encrypt(data, key, nonce=bytes([42])):
    aes = AES.new(bytes.fromhex(key), AES.MODE_EAX, nonce=nonce)
    ciphertext, _ = aes.encrypt_and_digest(
        pad(data.encode("utf-8"), BLOCK_SIZE)
    )
    return ciphertext.hex()


def decrypt(data, key, nonce=bytes([42])):
    aes = AES.new(bytes.fromhex(key), AES.MODE_EAX, nonce=nonce)
    plaintext = aes.decrypt(bytes.fromhex(data))
    return unpad(plaintext.decode("utf-8"), BLOCK_SIZE)
