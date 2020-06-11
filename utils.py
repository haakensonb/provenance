from Crypto.Hash import SHA256


def hash_func(input_str):
    return SHA256.new(input_str.encode()).hexdigest()
