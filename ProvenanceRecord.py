class ProvenanceRecord:
    """
    An object to hold all the data associated with a single provenance record.
    Each record will be placed in a list to form a provenance chain.
    This object is based of the record detailed in section IV. "MUTUAL
    AGREEMENT SIGNATURE SCHEME" of the associated paper.

    Attributes:
        username (str): identifier for user creating this record
        user_info (str): additional application specific user information
        modifications (list[Possible_Modifications]): list of enum objects
            that detail how the document was modified
        hashed_document (hexstr): result of hashing the document
        chain_info (list[RSAkey]): list of RSA public keys (using pycryptodome)
        Si (hexstr): user's symmetric key used to encrypt sensitive record data
        checksum (bytes): result of RSA signature function
        prev_record_signature (bytes): result of RSA signature function
        next_record_signature (bytes): result of RSA signature function
    """
    def __init__(
        self,
        username,
        user_info,
        modifications,
        hashed_document,
        chain_info,
        Si,
        checksum,
        prev_record_signature,
        next_record_signature=None
    ):
        self.username = username
        self.user_info = user_info
        self.modifications = modifications
        self.hashed_document = hashed_document
        self.chain_info = chain_info
        self.Si = Si
        self.checksum = checksum
        self.prev_record_signature = prev_record_signature
        self.next_record_signature = next_record_signature
