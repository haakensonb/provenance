from keys import keyPairs, auditor_keyPair
import RSAUtil
import utils
from iv import IVs
from enums import Signature_Status


class Auditor:
    """
    The Auditor verifies the integrity of a provenance chain
    that they are responsible for.

    Attributes:
        record_chain (list[ProvenanceRecord]): list of provenance records
        document (str): document that the provenance chain refers to

    """
    def __init__(self, record_chain, document):
        self.record_chain = record_chain
        self.document = document

    # Not sure if prov_id should be passed here?
    # Maybe this should be changed so that the Auditor gets a Provenance
    # object instead of a record_chain?
    def audit(self, prov_id):
        """
        The Auditor traverses and verifies the integrity of a provenance chain.
        Based on "Algorithm 2" in the paper.

        Args:
            prov_id (str): unique str to identify the provenance object

        Returns:
            (bool): Returns True if the provenance chain is valid.
                    Returns False if the chain has been tampered with.
        """
        # The Auditor hashes the document.
        H = utils.hash_func(self.document)
        # Make sure that the Auditor's hash matches the last document hash
        # in the chain.
        if H != self.record_chain[-1].hashed_document:
            return False
        # Traverse the records starting from the end of the chain
        for i, record in enumerate(reversed(self.record_chain)):
            # Verify the current signature field.
            hash_str = utils.get_checksum_str(
                record.user_info, record.modifications,
                record.hashed_document, record.Si
            )
            sig_val = RSAUtil.verify(
                keyPairs[record.username].publickey(),
                record.checksum,
                hash_str
            )
            if sig_val == Signature_Status.invalid.value:
                return False
            chain_info_str = utils.get_chain_info_str(record.chain_info)
            prev_data_last = utils.get_iv_signature_str(
                IVs[prov_id],
                chain_info_str,
                record.checksum
            )
            # The first record that was created involves the Auditor.
            # Since we are traversing the list in reverse order the last
            # record we visit is actually the first record.
            if i == (len(self.record_chain)-1):
                last_prev_sig = RSAUtil.verify(
                    auditor_keyPair.publickey(),
                    record.prev_record_signature,
                    prev_data_last
                )
                if last_prev_sig == Signature_Status.invalid.value:
                    return False
            # For the other records the Auditor's key isn't needed.
            if i < (len(self.record_chain)-1):
                prev_record = self.record_chain[::-1][i+1]
                if (prev_record.next_record_signature !=
                        record.prev_record_signature):
                    return False
                prev_data_str = utils.get_signature_str(
                    prev_record.hashed_document,
                    chain_info_str,
                    prev_record.checksum
                )
                # Verify the previous field of the current record.
                prev_sig = RSAUtil.verify(
                    keyPairs[prev_record.username].publickey(),
                    record.prev_record_signature,
                    prev_data_str
                )
                if prev_sig == Signature_Status.invalid.value:
                    return False
                # Verify the next field of the previous record.
                next_sig = RSAUtil.verify(
                    keyPairs[record.username].publickey(),
                    prev_record.next_record_signature,
                    prev_data_str
                )
                if next_sig == Signature_Status.invalid.value:
                    return False
        # If there are no integrity issues then just return True.
        return True
