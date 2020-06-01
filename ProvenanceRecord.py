import os
from hashlib import sha256
from Crypto.Cipher import AES

# this should be updated to reflect actual application
# maybe should be changed to enum
possible_modifications = {"created", "updated"}


def generate_key():
    return sha256(os.urandom(16)).hexdigest()


def hash_document(document):
    return sha256(document.encode()).hexdigest()


def encrypt(data, key):
    aes = AES.new(bytes.fromhex(key), AES.MODE_EAX)
    ciphertext, _ = aes.encrypt_and_digest(data)
    return ciphertext


def decrypt(data, key):
    aes = AES.new(bytes.fromhex(key), AES.MODE_EAX)
    plaintext = aes.decrypt(data)
    return plaintext


class ProvenanceRecord:
    def __init__(self, user_info, modifications, hashed_document, chain_info, sym_key, checksum=None, prev=None, next=None):
        self.user_info = user_info
        self.modifications = modifications
        self.hashed_document = hashed_document
        self.chain_info = chain_info
        self.sym_key = sym_key
        self.checksum = checksum
        self.prev = prev
        self.next = next


if __name__ == "__main__":
    print("hello")
    # need to add checking to make sure modification is valid
    modifications1 = ["created"]
    document1 = "test document number 1"
    test_key_auditor = generate_key()
    test_key_user1 = generate_key()
    chain_info1 = [test_key_auditor, test_key_user1]
    sym_key1 = encrypt(test_key_user1, test_key_auditor)
    pr1 = ProvenanceRecord("user1", modifications1, document1, chain_info1, sym_key1)
