from Crypto.Cipher import PKCS1_OAEP
from ProvenanceRecord import ProvenanceRecord
from enums import Possible_Modification
import AESUtil
import RSAUtil
import utils
from keys import keyPairs, auditor_keyPair, sym_keys
from iv import IVs


class Provenance:
    """
    The Provenance object provides a secure digital provenance record
    chain for a document.

    Attributes:
        prov_id (str): unique str for identification
        records (list[ProvenanceRecord]): list of provenance record objects
        current_record (int): index value for current record
        S (list[hexstr]): list of symmetric keys denoted as "S" in paper

    """
    def __init__(self, prov_id, records=[], current_record=0, S=[]):
        self.prov_id = prov_id
        self.records = records
        self.current_record = current_record
        self.S = S

    def create_record(self, username, user_info, document):
        """
        Creates and adds a provenance record to the record chain.
        Based on "Algorithm 1" in the paper.

        Args:
            username (str): string to identify user making record
            user_info (str): any other app specific info about the user
            document (str): document data that is to be secured

        Returns:
            void
        """
        # If there aren't any records, then create a first record.
        if not self.records:
            # User 1 information.
            user_info = AESUtil.encrypt(user_info, sym_keys[username])
            # Use auditor's key to encrypt the user's symmetric key.
            encryptor = PKCS1_OAEP.new(auditor_keyPair.publickey())
            Si = encryptor.encrypt(bytes.fromhex(sym_keys[username]))
            self.S.append(Si)
            # User 1 is the creator of the document.
            modifications = [Possible_Modification("created")]
            chain_info = [
                auditor_keyPair.publickey(),
                keyPairs[username].publickey()
            ]
            hashed_document = utils.hash_func(document)
            # Create the checksum.
            modifications_str = "".join([x.value for x in modifications])
            operations = AESUtil.encrypt(modifications_str, sym_keys[username])
            checksum_data = utils.get_checksum_str(
                user_info, operations, hashed_document, Si
            )
            checksum = RSAUtil.sign(keyPairs[username], checksum_data)
            # Create the previous digital signature.
            chain_info_str = utils.get_chain_info_str(chain_info)
            prev_data = utils.get_iv_signature_str(
                IVs[self.prov_id], chain_info_str, checksum
            )
            prev_record_signature = RSAUtil.sign(auditor_keyPair, prev_data)
            # Create the provenance record and add it to the record list.
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
            # Get the chain info from the previous record.
            # This uses a shallow copy, not sure if deep copy is needed.
            chain_info = self.records[self.current_record-1].chain_info[:]
            # Add the current user's public key to the chain.
            chain_info.append(keyPairs[username].publickey())
            chain_info_str = utils.get_chain_info_str(chain_info)
            # Create a signature for the previous record.
            prev_record = self.records[self.current_record-1]
            signature_str = utils.get_signature_str(
                prev_record.hashed_document,
                chain_info_str,
                prev_record.checksum
            )
            prev_record_signature = RSAUtil.sign(
                keyPairs[username],
                signature_str
            )
            # Update the previous record's next value.
            prev_record.next_record_signature = prev_record_signature
            # User then modifies the document in some way.
            # After which we encrypt the user's info using their symmetric key.
            user_info = AESUtil.encrypt(user_info, sym_keys[username])
            # The list of operations performed.
            modifications = [Possible_Modification("updated")]
            modifications_str = "".join([x.value for x in modifications])
            operations = AESUtil.encrypt(modifications_str, sym_keys[username])
            hashed_document = utils.hash_func(document)
            # Use the auditor's key to encrypt the user's symmetric key.
            encryptor = PKCS1_OAEP.new(auditor_keyPair.publickey())
            Si = encryptor.encrypt(bytes.fromhex(sym_keys[username]))
            self.S.append(Si)
            checksum_data = utils.get_checksum_str(
                user_info, operations, hashed_document, Si
            )
            checksum = RSAUtil.sign(keyPairs[username], checksum_data)
            # Create the provenance record.
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
