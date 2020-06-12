from Crypto.Hash import SHA256


def hash_func(input_str):
    return SHA256.new(input_str.encode()).hexdigest()


def get_chain_info_str(chain_info):
    return "".join([x.export_key(format='DER').hex() for x in chain_info])


def get_checksum_str(user_info, operations, hashed_document, Si):
    return f"{user_info}{operations}{hashed_document}{Si.hex()}"


def get_signature_str(hashed_document, chain_info_str, checksum):
    return f"{hashed_document}{chain_info_str}{checksum.hex()}"


# iv signature str
# still need to add iv
def get_iv_signature_str(chain_info_str, checksum):
    return f"{chain_info_str}{checksum.hex()}"
