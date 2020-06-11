from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from ProvenanceRecord import ProvenanceRecord
from enums import Possible_Modification
import AESUtil
import utils
from keys import keyPairs, auditor_keyPair, sym_keys


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
            prev_record_signature = self.sign(auditor_keyPair, prev_data)
            # create provenance record and add to record list
            self.records.append(ProvenanceRecord(
                username,
                user_info,
                operations,
                hashed_document,
                chain_info,
                Si,
                checksum,
                prev_record_signature
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
            prev_record_signature = self.sign(keyPairs[prev_record.username], signature_str)
            next_record_signature = self.sign(keyPairs[username], signature_str)
            # update prev record's next value
            prev_record.next_record_signature = next_record_signature

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
                prev_record_signature
            ))
