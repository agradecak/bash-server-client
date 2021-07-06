import os
from cryptography.hazmat.primitives import hashes, hmac

key = os.urandom(20)

poruka = "I kada sniježi, a spušta se tama, u pahuljama tišina je sama.".encode()

h = hmac.HMAC(key, hashes.MD5())
h.update(poruka)
hash_poruke = h.finalize()

print("Poruka", poruka, "ima hash", hash_poruke)

h_provjera = hmac.HMAC(key, hashes.MD5())
h_provjera.update(poruka)
h_provjera.verify(hash_poruke)

print()
