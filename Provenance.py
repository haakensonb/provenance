from Crypto.Cipher import PKCS1_OAEP
from ProvenanceRecord import ProvenanceRecord
from enums import Possible_Modification
import AESUtil
import RSAUtil
import utils
from keys import keyPairs, auditor_keyPair, sym_keys


class Provenance:
    def __init__(self, records=[], current_record=0, S=[]):
        self.records = records
        self.current_record = current_record
        self.S = S

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
            chain_info = [
                auditor_keyPair.publickey(),
                keyPairs[username].publickey()
            ]
            hashed_document = utils.hash_func(document)
            # create checksum
            modifications_str = "".join([x.value for x in modifications])
            operations = AESUtil.encrypt(modifications_str, sym_keys[username])
            checksum_data = utils.get_checksum_str(
                user_info, operations, hashed_document, Si
            )
            checksum = RSAUtil.sign(keyPairs[username], checksum_data)
            # create previous digital signature
            # missing auditor IV
            chain_info_str = utils.get_chain_info_str(chain_info)
            prev_data = utils.get_iv_signature_str(chain_info_str, checksum)
            prev_record_signature = RSAUtil.sign(auditor_keyPair, prev_data)
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
            chain_info_str = utils.get_chain_info_str(chain_info)
            # create signature for previous record
            prev_record = self.records[self.current_record-1]
            signature_str = utils.get_signature_str(
                prev_record.hashed_document,
                chain_info_str,
                prev_record.checksum
            )
            prev_record_signature = RSAUtil.sign(
                keyPairs[prev_record.username],
                signature_str
            )
            next_record_signature = RSAUtil.sign(
                keyPairs[username],
                signature_str
            )
            # update prev record's next value
            prev_record.next_record_signature = next_record_signature
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
            # checksum_data = f"{user_info}{operations}{hashed_document}{Si.hex()}"
            checksum_data = utils.get_checksum_str(
                user_info, operations, hashed_document, Si
            )
            checksum = RSAUtil.sign(keyPairs[username], checksum_data)
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
