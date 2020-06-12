from keys import keyPairs, auditor_keyPair
import RSAUtil
import utils


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
            sig_val = RSAUtil.verify(
                keyPairs[record.username].publickey(),
                record.checksum,
                hash_str
            )
            # signature values should be enums
            if sig_val == 'invalid signature':
                return False

            # still need to add an IV
            chain_info_str = utils.get_chain_info_str(record.chain_info)
            prev_data_last = f"{chain_info_str}{record.checksum.hex()}"

            # if Pi = P1
            # last record in the reversed order involves auditor
            if i == (len(self.record_chain)-1):
                last_prev_sig = RSAUtil.verify(
                    auditor_keyPair.publickey(),
                    record.prev_record_signature,
                    prev_data_last
                )
                if last_prev_sig == 'invalid signature':
                    return False

            if i < (len(self.record_chain)-1):
                prev_record = self.record_chain[::-1][i+1]
                prev_data_str = f"{prev_record.hashed_document}{chain_info_str}{prev_record.checksum.hex()}"
                # verify the previous field of the current record
                prev_sig = RSAUtil.verify(
                    keyPairs[prev_record.username].publickey(),
                    record.prev_record_signature,
                    prev_data_str
                )
                if prev_sig == 'invalid signature':
                    return False
                # verify the next field of the next record (record order is reversed)
                # still need to add an IV
                next_sig = RSAUtil.verify(
                    keyPairs[record.username].publickey(),
                    prev_record.next_record_signature,
                    prev_data_str
                )
                if next_sig == 'invalid signature':
                    return False

        return True
