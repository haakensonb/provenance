from Provenance import Provenance
from Auditor import Auditor


if __name__ == "__main__":
    print("hello")
    # need to add checking to make sure modification is valid
    # modifications1 = ["created"]
    username1 = "user1"
    user_info1 = "blah blah"
    document1 = "test document number 1"
    # test_key_auditor = generate_key()
    # print(f"auditor key: {test_key_auditor}")
    # test_key_user1 = generate_key()
    # print(f"user key {test_key_user1}")
    # chain_info1 = [test_key_auditor, test_key_user1]
    # sym_key1 = encrypt(test_key_user1, test_key_auditor)
    # print(f"sym_key enc: {sym_key1}")
    # print(f"sym_key dec: {decrypt(sym_key1, test_key_auditor)}")
    # pr1 = ProvenanceRecord("user1", modifications1, document1, chain_info1, sym_key1)

    # key = RSA.generate(bits=3072)
    # print(f"keyPair: {key}")
    # h = SHA256.new(user_info1.encode("utf-8"))
    # print(f"hash: {h}")
    # signature = pkcs1_15.new(key).sign(h)
    # print(f"signature: {signature}")

    # pub = key.publickey()
    # # binary representation of the pub key
    # print(f"pub: {pub.export_key(format='DER')}")
    # h = SHA256.new(b"blahblah")
    # try:
    #     pkcs1_15.new(pub).verify(h, signature)
    #     print("valid sign")
    # except (ValueError, TypeError):
    #     print("invalid sign")

    pr = Provenance()
    pr.create_record(username1, user_info1, document1)
    pr.create_record("user2", "blah balh", document1)
    a = Auditor(pr.records, document1)
    print(a.audit())
