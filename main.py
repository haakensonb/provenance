from Provenance import Provenance
from Auditor import Auditor
from utils import gen_random_hex_str
from iv import IVs


if __name__ == "__main__":
    username1 = "user1"
    user_info1 = "blah blah"
    document1 = "test document number 1"
    # Create IV for document.
    # This will be changed so that the Auditor is the
    # only one with acces to it.
    doc_iv = gen_random_hex_str()
    prov_id = 'prov1'
    IVs[prov_id] = doc_iv
    pr = Provenance(prov_id)
    pr.create_record(username1, user_info1, document1)
    pr.create_record("user2", "blah balh", document1)
    a = Auditor(pr.records, document1)
    print(a.audit(prov_id))
