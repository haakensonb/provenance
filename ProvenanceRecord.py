from hashlib import sha256
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from enum import Enum
from copy import deepcopy

# very dirty code right now

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
    def __init__(self, username, user_info, modifications, hashed_document, chain_info, Si, checksum, prev, next=None):
        self.username = username
        self.user_info = user_info
        self.modifications = modifications
        self.hashed_document = hashed_document
        self.chain_info = chain_info
        self.Si = Si
        self.checksum = checksum
        self.prev = prev
        self.next = next


# temporary global for testing keys
# actual user keys will be stored in database
keyPairs = {'user1': RSA.generate(bits=3072), 'user2': RSA.generate(bits=3072)}
sym_keys = {'user1': SHA256.new(get_random_bytes(16)).hexdigest(), 'user2': SHA256.new(get_random_bytes(16)).hexdigest()}
auditor_keyPair = RSA.generate(bits=3072)


class Provenance:
    def __init__(self, records=[], current_record=0, S=[]):
        self.records = records
        self.current_record = current_record
        self.S = S

    def sign(self, rsa_key, data_str):
        h = SHA256.new(data_str.encode("utf-8"))
        signature = pkcs1_15.new(rsa_key).sign(h)
        return signature

    def verify(self, rsa_pub_key, signature, data_str):
        h = SHA256.new(data_str.encode("utf-8"))
        try:
            pkcs1_15.new(rsa_pub_key).verify(h, signature)
            return "valid signature"
        except (ValueError, TypeError):
            return "invalid signature"

    def create_record(self, username, user_info, document):
        # if there aren't any records
        # then create a first record
        if not self.records:
            # User 1 information
            # using sym enc
            user_info = encrypt(user_info, sym_keys[username])
            # use auditor key to enc sym key
            encryptor = PKCS1_OAEP.new(auditor_keyPair.publickey())
            Si = encryptor.encrypt(bytes.fromhex(sym_keys[username]))
            self.S.append(Si)
            # User 1 is creator of Document
            modifications = [Possible_Modification("created")]
            # public keys are objects, but I'm not sure if
            # this part should use a str representation of them instead?
            chain_info = [auditor_keyPair.publickey(), keyPairs[username].publickey()]
            hashed_document = hash_document(document)
            # create checksum
            modifications_str = "".join([x.value for x in modifications])
            operations = encrypt(modifications_str, sym_keys[username])
            checksum_data = f"{user_info}{operations}{hashed_document}{Si.hex()}"
            checksum = self.sign(keyPairs[username], checksum_data)
            # create previous digital signature
            # missing auditor IV
            chain_info_str = "".join([x.export_key(format='DER').hex() for x in chain_info])
            prev_data = f"{chain_info_str}{checksum.hex()}"
            prev = self.sign(auditor_keyPair, prev_data)
            # create provenance record and add to record list
            self.records.append(ProvenanceRecord(
                username,
                user_info,
                operations,
                hashed_document,
                chain_info,
                Si,
                checksum,
                prev
            ))

        else:
            self.current_record += 1
            # get the chain info from the previous record
            # not sure if deepcopy is actually needed here
            chain_info = self.records[self.current_record-1].chain_info
            # add the current user key to the chain
            chain_info.append(keyPairs[username].publickey())
            # need to make a function for this
            chain_info_str = "".join([x.export_key(format='DER').hex() for x in chain_info])
            # create signature for previous record
            prev_record = self.records[-1]
            signature_str = f"{prev_record.hashed_document}{chain_info_str}{prev_record.checksum}"
            prev = self.sign(keyPairs[prev_record.username], signature_str)
            # update prev record's next value
            prev_record.next = prev
            # user modifies document in some way
            # then encrypt user info
            user_info = encrypt(user_info, sym_keys[username])
            # list of operations performed
            modifications = [Possible_Modification("updated")]
            modifications_str = "".join([x.value for x in modifications])
            operations = encrypt(modifications_str, sym_keys[username])
            hashed_document = hash_document(document)
             # use auditor key to enc sym key
            encryptor = PKCS1_OAEP.new(auditor_keyPair.publickey())
            Si = encryptor.encrypt(bytes.fromhex(sym_keys[username]))
            self.S.append(Si)
            checksum_data = f"{user_info}{operations}{hashed_document}{Si.hex()}"
            checksum = self.sign(keyPairs[username], checksum_data)
            # create record
            self.records.append(ProvenanceRecord(
                username,
                user_info,
                operations,
                hashed_document,
                chain_info,
                Si,
                checksum,
                prev
            ))



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

    # key = RSA.generate(bits=3072)
    # print(f"keyPair: {key}")
    # h = SHA256.new(user_info1.encode("utf-8"))
    # print(f"hash: {h}")
    # signature = pkcs1_15.new(key).sign(h)
    # print(f"signature: {signature}")

    # pub = key.publickey()
    # # binary representation of the pub key
    # print(f"pub: {pub.export_key(format='DER')}")
    # h = SHA256.new(b"blahblah")
    # try:
    #     pkcs1_15.new(pub).verify(h, signature)
    #     print("valid sign")
    # except (ValueError, TypeError):
    #     print("invalid sign")

    pr = Provenance()
    pr.create_record(username1, user_info1, document1)
    pr.create_record("user2", "blah balh", document1)
