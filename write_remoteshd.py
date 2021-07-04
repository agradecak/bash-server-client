import configparser
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# stvaranje privatnog kljuca
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(b'1234')
)

# stvaranje javnog kljuca
public_key = private_key.public_key()

public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.PKCS1
)

# pisanje kljuceva i porta u remoteshd.conf
config = configparser.ConfigParser()

config['DEFAULT'] = {}
config['DEFAULT']['key_prv'] = private_key_pem.decode()
config['DEFAULT']['key_pub'] = public_key_pem.decode()
config['DEFAULT']['port'] = '5000'

with open('remoteshd.conf', 'w') as configfile:
    config.write(configfile)

configfile.close()