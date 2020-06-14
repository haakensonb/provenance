from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from enums import Signature_Status


def sign(rsa_key, data_str):
    """
    Uses a RSA key to create a PKCS#1 v1.5 signature of a message.

    Args:
        rsa_key (RSAkey): pycryptodome RSAkey object
        data_str (str): data to be signed in string format
    Returns:
        (bytes): resulting signature in bytes format
    """
    h = SHA256.new(data_str.encode("utf-8"))
    signature = pkcs1_15.new(rsa_key).sign(h)
    return signature


def verify(rsa_pub_key, signature, data_str):
    """
    Uses a RSA public key to verify a PKCS#1 v1.5 message signature.

    Args:
        rsa_pub_key (RSAkey): pycryptodome RSA public key object
        signature (bytes): signature in bytes format
        data_str (str): data to be verified against signature
    """
    h = SHA256.new(data_str.encode("utf-8"))
    try:
        pkcs1_15.new(rsa_pub_key).verify(h, signature)
        return Signature_Status("valid signature")
    except (ValueError, TypeError):
        return Signature_Status("invalid signature")
