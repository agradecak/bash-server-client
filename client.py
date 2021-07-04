import os, configparser, socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet


# ctx = SSL.Context(SSL.TLSv1_2_METHOD)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# ssock = SSL.Connection(ctx, sock)
sock.connect(('localhost', 5000))

# primanje adrese i socketa
primljeni_podaci = sock.recv(1024)
print(primljeni_podaci.decode())

print('')

# slanje korisnickog imena
print('Korisnicko ime:')
poruka = input()
podaci = poruka.encode()
sock.send(podaci)

print('')

# slanje zaporke
print('Zaporka:')
poruka = input()
podaci = poruka.encode()
sock.send(podaci)

# primanje odgovora
primljeni_podaci = sock.recv(1024)
print(primljeni_podaci.decode())

# generiranje simetricnog kljuca
symmetric_key_client = Fernet.generate_key()
f = Fernet(symmetric_key_client)
print(symmetric_key_client)

# citanje javnog kljuca
config = configparser.ConfigParser()
config.read('remoteshd.conf')
public_key = bytes(config['DEFAULT']['key_pub'], encoding='utf-8')

public_key = serialization.load_pem_public_key(
    public_key
    )
print(public_key)

# enkripcija javnim kljucem
ciphertext = public_key.encrypt(
    symmetric_key_client,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print(ciphertext)

# slanje simetricnog kljuca
podaci = ciphertext
sock.send(podaci)

encrypted_message = f.encrypt(b'dora rocks')
sock.send(encrypted_message)

# ssock.shutdown()
sock.close()