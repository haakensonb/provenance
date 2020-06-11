from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


# temporary global for testing keys
# actual user keys will be stored in database
keyPairs = {'user1': RSA.generate(bits=3072), 'user2': RSA.generate(bits=3072)}
sym_keys = {'user1': SHA256.new(get_random_bytes(16)).hexdigest(), 'user2': SHA256.new(get_random_bytes(16)).hexdigest()}
auditor_keyPair = RSA.generate(bits=3072)
