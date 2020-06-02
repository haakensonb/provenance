from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from enum import Enum
from copy import deepcopy


# this should be updated to reflect actual application
class Possible_Modification(Enum):
    created = "created"
    updated = "updated"


# AES block size
BLOCK_SIZE = 16


def hash_document(document):
    return sha256(document.encode()).hexdigest()


def encrypt(data, key, nonce=bytes([42])):
    aes = AES.new(bytes.fromhex(key), AES.MODE_EAX, nonce=nonce)
    ciphertext, _ = aes.encrypt_and_digest(pad(data.encode("utf-8"), BLOCK_SIZE))
    return ciphertext.hex()


def decrypt(data, key, nonce=bytes([42])):
    aes = AES.new(bytes.fromhex(key), AES.MODE_EAX, nonce=nonce)
    plaintext = aes.decrypt(bytes.fromhex(data))
    return unpad(plaintext.decode("utf-8"), BLOCK_SIZE)


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


# temporary global for testing keys
# actual user keys will be stored in database
user_keys = {'user1': get_random_bytes(16).hex(), 'user2': get_random_bytes(16).hex()}
auditor_key = get_random_bytes(16).hex()


class Provenance:
    def __init__(self, records=[], current_record=0, sym_keys=[]):
        self.records = records
        self.current_record = current_record
        self.sym_keys = sym_keys

    def create_record(self, username, user_info, document):
        # if there aren't any records
        # then create a first record
        if not self.records:
            # User 1 information
            user_info = encrypt(user_info, user_keys[username])
            sym_key = encrypt(user_keys[username], auditor_key)
            self.sym_keys.append(sym_key)
            # User 1 is creator of Document
            modifications = Possible_Modification("created")
            chain_info = [auditor_key, user_keys[username]]
            hashed_document = hash_document(document)
            # create provenance record and add to record list
            self.records.append(ProvenanceRecord(
                user_info,
                modifications,
                hashed_document,
                chain_info,
                sym_key
            ))

        else:
            # get the chain info from the previous record
            # not sure if deepcopy is actually needed here
            chain_info = deepcopy(self.records[self.current_record-1].chain_info)
            # add the current user key to the chain
            chain_info.append(user_keys[username])



if __name__ == "__main__":
    print("hello")
    # need to add checking to make sure modification is valid
    # modifications1 = ["created"]
    username1 = "user1"
    user_info1 = "blah blah"
    document1 = "test document number 1"
    # test_key_auditor = generate_key()
    # print(f"auditor key: {test_key_auditor}")
    # test_key_user1 = generate_key()
    # print(f"user key {test_key_user1}")
    # chain_info1 = [test_key_auditor, test_key_user1]
    # sym_key1 = encrypt(test_key_user1, test_key_auditor)
    # print(f"sym_key enc: {sym_key1}")
    # print(f"sym_key dec: {decrypt(sym_key1, test_key_auditor)}")
    # pr1 = ProvenanceRecord("user1", modifications1, document1, chain_info1, sym_key1)
    pr = Provenance()
    pr.create_record(username1, user_info1, document1)
