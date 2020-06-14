from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from constants import BLOCK_SIZE


def encrypt(data, key, nonce=bytes([42])):
    """
    Uses AES (EAX mode) to encrypt data.

    Args:
        data (str): string that can be encoded to bytes using utf-8
        key (hexstr): symmetric key in hex that can be converted to bytes

    Returns:
        ciphertext (hexstr): data encrypted in hex string format
    """
    aes = AES.new(bytes.fromhex(key), AES.MODE_EAX, nonce=nonce)
    ciphertext, _ = aes.encrypt_and_digest(
        # Data must be padded to fit correct block size.
        pad(data.encode("utf-8"), BLOCK_SIZE)
    )
    return ciphertext.hex()


def decrypt(data, key, nonce=bytes([42])):
    """
    Uses AES (EAX mode) to decrypt data.

    Args:
        data (hexstr): ciphertext in hex string format
        key (hexstr): symmetric key in hex string format

    Returns:
        plaintext (str): decrypted plaintext string in utf-8 format
    """
    aes = AES.new(bytes.fromhex(key), AES.MODE_EAX, nonce=nonce)
    plaintext = aes.decrypt(bytes.fromhex(data))
    # The padding of the data must be removed with unpad.
    return unpad(plaintext.decode("utf-8"), BLOCK_SIZE)
