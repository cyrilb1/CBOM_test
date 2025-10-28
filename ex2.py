from cryptography.fernet import Fernet, MultiFernet
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#### The recipes layers: high-level functions

### Symmetric encyption

## Fernet: used for symmetric encryption


# Ex1
key = Fernet.generate_key() # Recognized by CBOMkit
f = Fernet(key)
token = f.encrypt(b"Secret message")

f.decrypt(token)


# Ex2
key = Fernet.generate_key() # Recognized by CBOMkit
f = Fernet(key)
token = f.encrypt(b"Secret message")

f.decrypt(token)

timestamp = f.extract_timestamp(token)
current_time = time.time()
token_with_time = f.encrypt_at_time(b"Another message", current_time)
f.decrypt_at_time(token, ttl=60, current_time=current_time)


# Ex3: example using hazmat functions
password = b"password"
salt = os.urandom(16)

kdf = PBKDF2HMAC( # Recognized by CBOMkit
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=1_200_000,
)

key = base64.urlsafe_b64encode(kdf.derive(password))
f = Fernet(key)
token = f.encrypt(b"Secret message!")

f.decrypt(token)


# Ex4
key1 = Fernet(Fernet.generate_key()) # Recognized by CBOMkit
key2 = Fernet(Fernet.generate_key()) # Recognized by CBOMkit
f = MultiFernet([key1, key2])
token = f.encrypt(b"Secret message")

f.decrypt(token)


key3 = Fernet(Fernet.generate_key()) # Recognized by CBOMkit
f2 = f = MultiFernet([key3, key1, key2])
rotated = f2.rotate(token)

f2.decrypt(rotated)


### Non-symmetric encryption (pas sur verifier)

## X.509

# Ex1:



#### The hazmat levels: more low-level functions

### Authenticated encryption

# Ex1: ChaCha20Poly1305
import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

data = b"a secret message"
aad = b"authenticated but unencrypted data"

key = ChaCha20Poly1305.generate_key() # Recognized by CBOMkit
chacha = ChaCha20Poly1305(key)
nonce = os.urandom(12)
ct = chacha.encrypt(nonce, data, aad)

chacha.decrypt(nonce, ct, aad)


# Ex2: AESGCM
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

data = b"a secret message"
aad = b"authenticated but unencrypted data"

key = AESGCM.generate_key(bit_length=128) # Recognized by CBOMkit
aesgcm = AESGCM(key)
nonce = os.urandom(12)
ct = aesgcm.encrypt(nonce, data, aad)

aesgcm.decrypt(nonce, ct, aad)


# Ex3: AESGCMSIV
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

data = b"a secret message"
aad = b"authenticated but unencrypted data"

key = AESGCMSIV.generate_key(bit_length=128)
aesgcmsiv = AESGCMSIV(key)
nonce = os.urandom(12)
ct = aesgcmsiv.encrypt(nonce, data, aad)

aesgcmsiv.decrypt(nonce, ct, aad)


# Ex4: AESOCB3
import os
from cryptography.hazmat.primitives.ciphers.aead import AESOCB3

data = b"a secret message"
aad = b"authenticated but unencrypted data"

key = AESOCB3.generate_key(bit_length=128) # Recognized by CBOMkit
aesocb = AESOCB3(key)
nonce = os.urandom(12)
ct = aesocb.encrypt(nonce, data, aad)

aesocb.decrypt(nonce, ct, aad)


# Ex5: AESSIV
import os
from cryptography.hazmat.primitives.ciphers.aead import AESSIV

data = b"a secret message"
nonce = os.urandom(16)

aad = [b"authenticated but unencrypted data", nonce]
key = AESSIV.generate_key(bit_length=512) # Recognized by CBOMkit
aessiv = AESSIV(key)
ct = aessiv.encrypt(data, aad)

# Utilisation de encrypt_into
buf = bytearray(64)  # Buffer pré-alloué
aessiv.encrypt_into(data, aad, buf)

aessiv.decrypt(ct, aad)


# Ex6: AESCCM
import os
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

data = b"a secret message"
aad = b"authenticated but unencrypted data"

key = AESCCM.generate_key(bit_length=128) # Recognized by CBOMkit
aesccm = AESCCM(key)
nonce = os.urandom(13)
ct = aesccm.encrypt(nonce, data, aad)

aesccm.decrypt(nonce, ct, aad)
