from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from enums import Signature_Status


def sign(rsa_key, data_str):
    h = SHA256.new(data_str.encode("utf-8"))
    signature = pkcs1_15.new(rsa_key).sign(h)
    return signature


def verify(rsa_pub_key, signature, data_str):
    h = SHA256.new(data_str.encode("utf-8"))
    try:
        pkcs1_15.new(rsa_pub_key).verify(h, signature)
        return Signature_Status("valid signature")
    except (ValueError, TypeError):
        return Signature_Status("invalid signature")
