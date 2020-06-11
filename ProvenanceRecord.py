class ProvenanceRecord:
    def __init__(self, username, user_info, modifications, hashed_document, chain_info, Si, checksum, prev_record, next_record=None):
        self.username = username
        self.user_info = user_info
        self.modifications = modifications
        self.hashed_document = hashed_document
        self.chain_info = chain_info
        self.Si = Si
        self.checksum = checksum
        self.prev_record = prev_record
        self.next_record = next_record
