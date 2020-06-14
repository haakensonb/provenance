from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes


def gen_random_hex_str(num_of_bytes=16):
    """
    Generates some random bytes that are hashed using SHA256 to create a
    hex string. This hex string can then be used as a key.

    Args:
        num_of_bytes (int): how many random bytes to generate before hashing

    Returns:
        (hexstr): returns a 64 digit hex string (32 bytes)
    """
    return SHA256.new(get_random_bytes(num_of_bytes)).hexdigest()


def hash_func(input_str):
    """
    Uses SHA256 to hash an input string.
    """
    return SHA256.new(input_str.encode()).hexdigest()


def get_chain_info_str(chain_info):
    """
    Takes in a chain_info list of RSA public keys and returns them
    concatenated as a hex string.
    """
    return "".join([x.export_key(format='DER').hex() for x in chain_info])


def get_checksum_str(user_info, operations, hashed_document, Si):
    """
    Returns a string with the proper formatting for
    a provenance record checksum.
    """
    return f"{user_info}{operations}{hashed_document}{Si.hex()}"


def get_signature_str(hashed_document, chain_info_str, checksum):
    """
    Returns a string with the proper formatting for
    a provenance record previous/next signature.
    """
    return f"{hashed_document}{chain_info_str}{checksum.hex()}"


def get_iv_signature_str(iv, chain_info_str, checksum):
    """
    Returns a string with a proper formatting for the
    initial record signature string that includes an IV.
    """
    return f"{iv}{chain_info_str}{checksum.hex()}"
