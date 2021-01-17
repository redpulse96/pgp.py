from pgpy.constants import PubKeyAlgorithm, EllipticCurveOID, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
from datetime import timedelta
import pgpy

# we can start by generating a primary key. For this example, we'll use RSA, but it could be DSA or ECDSA as well
key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)

#new user id for the key
uid = pgpy.PGPUID.new('Spyros Grammatakis', comment='Honest user', email='test@test.com')

# add the new user id to the key
key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
            hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512, HashAlgorithm.SHA224],
            ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
            compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed],
			key_expires=timedelta(days=365))
#print("Private primary key before adding subkey")
#print(key)
#print("Public primary key before adding subkey")
#print(key.pubkey)

# protect primary private key with passphrase
key.protect("primary", SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)

# generate a sub key.
subkey = pgpy.PGPKey.new(PubKeyAlgorithm.ECDH, EllipticCurveOID.NIST_P256)
#print(subkey)

# protect subkey private key with passphraee
subkey.protect("sub", SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)

# preferences that are specific to the subkey can be chosen here
#print("Private sub key after adding subkey")
#print(subkey)
#print("Public sub key after adding subkey")
#print(subkey.pubkey)

# compressed by default with ZIP DEFLATE
message = pgpy.PGPMessage.new("This is the new message!")

#sign key and message
with key.unlock("primary"):
	assert key.is_unlocked
	message |= key.sign(message)
	with subkey.unlock("sub"):
		assert subkey.is_unlocked
		key.add_subkey(subkey, usage={KeyFlags.Authentication})
		subkey.pubkey |= key.certify(subkey.pubkey)
	assert subkey.is_unlocked is False
assert key.is_unlocked is False
