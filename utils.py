from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes


def gen_random_hex_str(num_of_bytes=16):
    return SHA256.new(get_random_bytes(num_of_bytes)).hexdigest()


def hash_func(input_str):
    return SHA256.new(input_str.encode()).hexdigest()


def get_chain_info_str(chain_info):
    return "".join([x.export_key(format='DER').hex() for x in chain_info])


def get_checksum_str(user_info, operations, hashed_document, Si):
    return f"{user_info}{operations}{hashed_document}{Si.hex()}"


def get_signature_str(hashed_document, chain_info_str, checksum):
    return f"{hashed_document}{chain_info_str}{checksum.hex()}"


def get_iv_signature_str(iv, chain_info_str, checksum):
    return f"{iv}{chain_info_str}{checksum.hex()}"
