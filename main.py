from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from enums import Possible_Modification
from ProvenanceRecord import ProvenanceRecord
import AESUtil
import utils


# temporary global for testing keys
# actual user keys will be stored in database
keyPairs = {'user1': RSA.generate(bits=3072), 'user2': RSA.generate(bits=3072)}
sym_keys = {'user1': SHA256.new(get_random_bytes(16)).hexdigest(), 'user2': SHA256.new(get_random_bytes(16)).hexdigest()}
auditor_keyPair = RSA.generate(bits=3072)


class Auditor:
    def __init__(self, record_chain, document):
        self.record_chain = record_chain
        self.document = document

    def audit(self):
        # auditor hashes document
        H = utils.hash_func(self.document)
        # make sure auditor's hash matches last document hash in the chain
        if H != self.record_chain[-1].hashed_document:
            return False
        for i, record in enumerate(reversed(self.record_chain)):
            # verify the current signature field
            # should make method for formatting checksum string data
            hash_str = f"{record.user_info}{record.modifications}{record.hashed_document}{record.Si.hex()}"
            sig_val = Provenance.verify(keyPairs[record.username].publickey(), record.checksum, hash_str)
            # signature values should be enums
            if sig_val == 'invalid signature':
                return False

            # still need to add an IV
            chain_info_str = "".join([x.export_key(format='DER').hex() for x in record.chain_info])
            prev_data_last = f"{chain_info_str}{record.checksum.hex()}"

            # if Pi = P1
            # last record in the reversed order involves auditor
            if i == (len(self.record_chain)-1):
                last_prev_sig = Provenance.verify(auditor_keyPair.publickey(), record.prev, prev_data_last)
                if last_prev_sig == 'invalid signature':
                    return False

            if i < (len(self.record_chain)-1):
                prev_record = self.record_chain[::-1][i+1]
                prev_data_str = f"{prev_record.hashed_document}{chain_info_str}{prev_record.checksum.hex()}"
                # verify the previous field of the current record
                prev_sig = Provenance.verify(keyPairs[prev_record.username].publickey(), record.prev, prev_data_str)
                if prev_sig == 'invalid signature':
                    return False
                # verify the next field of the next record (record order is reversed)
                # next_record = self.record_chain[i+1]
                # still need to add an IV
                # next_chain_info_str = "".join([x.export_key(format='DER').hex() for x in prev_record.chain_info])
                # next_data = f"{prev_record.hashed_document}{next_chain_info_str}{prev_record.checksum.hex()}"
                next_sig = Provenance.verify(keyPairs[record.username].publickey(), prev_record.next, prev_data_str)
                if next_sig == 'invalid signature':
                    return False

        return True


class Provenance:
    def __init__(self, records=[], current_record=0, S=[]):
        self.records = records
        self.current_record = current_record
        self.S = S

    def sign(self, rsa_key, data_str):
        h = SHA256.new(data_str.encode("utf-8"))
        signature = pkcs1_15.new(rsa_key).sign(h)
        return signature

    # this need to be moved to its own class
    @staticmethod
    def verify(rsa_pub_key, signature, data_str):
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
            user_info = AESUtil.encrypt(user_info, sym_keys[username])
            # use auditor key to enc sym key
            encryptor = PKCS1_OAEP.new(auditor_keyPair.publickey())
            Si = encryptor.encrypt(bytes.fromhex(sym_keys[username]))
            self.S.append(Si)
            # User 1 is creator of Document
            modifications = [Possible_Modification("created")]
            # public keys are objects, but I'm not sure if
            # this part should use a str representation of them instead?
            chain_info = [auditor_keyPair.publickey(), keyPairs[username].publickey()]
            hashed_document = utils.hash_func(document)
            # create checksum
            modifications_str = "".join([x.value for x in modifications])
            operations = AESUtil.encrypt(modifications_str, sym_keys[username])
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
            # shallow copy
            chain_info = self.records[self.current_record-1].chain_info[:]
            # add the current user key to the chain
            chain_info.append(keyPairs[username].publickey())
            # need to make a function for this
            chain_info_str = "".join([x.export_key(format='DER').hex() for x in chain_info])
            # create signature for previous record
            prev_record = self.records[self.current_record-1]
            signature_str = f"{prev_record.hashed_document}{chain_info_str}{prev_record.checksum.hex()}"
            prev = self.sign(keyPairs[prev_record.username], signature_str)
            next = self.sign(keyPairs[username], signature_str)
            # update prev record's next value
            prev_record.next = next

            # self.records[self.current_record-1].next = self.sign(keyPairs)
            # user modifies document in some way
            # then encrypt user info
            user_info = AESUtil.encrypt(user_info, sym_keys[username])
            # list of operations performed
            modifications = [Possible_Modification("updated")]
            modifications_str = "".join([x.value for x in modifications])
            operations = AESUtil.encrypt(modifications_str, sym_keys[username])
            hashed_document = utils.hash_func(document)
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
    a = Auditor(pr.records, document1)
    print(a.audit())
