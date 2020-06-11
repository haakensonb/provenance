class ProvenanceRecord:
    def __init__(self, username, user_info, modifications, hashed_document, chain_info, Si, checksum, prev_record_signature, next_record_signature=None):
        self.username = username
        self.user_info = user_info
        self.modifications = modifications
        self.hashed_document = hashed_document
        self.chain_info = chain_info
        self.Si = Si
        self.checksum = checksum
        self.prev_record_signature = prev_record_signature
        self.next_record_signature = next_record_signature
