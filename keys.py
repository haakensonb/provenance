from Crypto.PublicKey import RSA
from utils import gen_random_hex_str


# temporary global for testing keys
# actual user keys will be stored in database
keyPairs = {'user1': RSA.generate(bits=3072), 'user2': RSA.generate(bits=3072)}
sym_keys = {
    'user1': gen_random_hex_str(),
    'user2': gen_random_hex_str()
}
auditor_keyPair = RSA.generate(bits=3072)
