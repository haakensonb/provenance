from Provenance import Provenance
from Auditor import Auditor


if __name__ == "__main__":
    username1 = "user1"
    user_info1 = "blah blah"
    document1 = "test document number 1"

    pr = Provenance()
    pr.create_record(username1, user_info1, document1)
    pr.create_record("user2", "blah balh", document1)
    a = Auditor(pr.records, document1)
    print(a.audit())
