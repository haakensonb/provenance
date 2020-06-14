from Crypto.PublicKey import RSA
from utils import gen_random_hex_str


# Temporary globals to hold keys for prototype version.
# In the actual application user keys will be stored in the database.
keyPairs = {'user1': RSA.generate(bits=3072), 'user2': RSA.generate(bits=3072)}
sym_keys = {
    'user1': gen_random_hex_str(),
    'user2': gen_random_hex_str()
}
auditor_keyPair = RSA.generate(bits=3072)
