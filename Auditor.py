from keys import keyPairs, auditor_keyPair
import RSAUtil
import utils
from iv import IVs
from enums import Signature_Status


class Auditor:
    def __init__(self, record_chain, document):
        self.record_chain = record_chain
        self.document = document

    # Not sure if prov_id should be passed here?
    # Maybe change so that Auditor gets Provenance obj instead of record_chain?
    def audit(self, prov_id):
        # auditor hashes document
        H = utils.hash_func(self.document)
        # make sure auditor's hash matches last document hash in the chain
        if H != self.record_chain[-1].hashed_document:
            return False
        for i, record in enumerate(reversed(self.record_chain)):
            # verify the current signature field
            hash_str = utils.get_checksum_str(
                record.user_info, record.modifications,
                record.hashed_document, record.Si
            )
            sig_val = RSAUtil.verify(
                keyPairs[record.username].publickey(),
                record.checksum,
                hash_str
            )
            # signature values should be enums
            if sig_val == Signature_Status.invalid.value:
                return False

            # still need to add an IV
            chain_info_str = utils.get_chain_info_str(record.chain_info)
            prev_data_last = utils.get_iv_signature_str(
                IVs[prov_id],
                chain_info_str,
                record.checksum
            )

            # if Pi = P1
            # last record in the reversed order involves auditor
            if i == (len(self.record_chain)-1):
                last_prev_sig = RSAUtil.verify(
                    auditor_keyPair.publickey(),
                    record.prev_record_signature,
                    prev_data_last
                )
                if last_prev_sig == Signature_Status.invalid.value:
                    return False

            if i < (len(self.record_chain)-1):
                prev_record = self.record_chain[::-1][i+1]
                prev_data_str = utils.get_signature_str(
                    prev_record.hashed_document,
                    chain_info_str,
                    prev_record.checksum
                )
                # verify the previous field of the current record
                prev_sig = RSAUtil.verify(
                    keyPairs[prev_record.username].publickey(),
                    record.prev_record_signature,
                    prev_data_str
                )
                if prev_sig == Signature_Status.invalid.value:
                    return False
                # verify the next field of the next record (record order is reversed)
                # still need to add an IV
                next_sig = RSAUtil.verify(
                    keyPairs[record.username].publickey(),
                    prev_record.next_record_signature,
                    prev_data_str
                )
                if next_sig == Signature_Status.invalid.value:
                    return False

        return True
