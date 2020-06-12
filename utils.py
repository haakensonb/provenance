from Crypto.Hash import SHA256


def hash_func(input_str):
    return SHA256.new(input_str.encode()).hexdigest()


def get_chain_info_str(chain_info):
    return "".join([x.export_key(format='DER').hex() for x in chain_info])


def get_checksum_str(user_info, operations, hashed_document, Si):
    return f"{user_info}{operations}{hashed_document}{Si.hex()}"


# signature str
# iv signature str