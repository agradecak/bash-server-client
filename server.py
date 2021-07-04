import configparser, socket, crypt
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
from hmac import compare_digest as compare_hash


remoteConfig = configparser.ConfigParser()
remoteConfig.read('remoteshd.conf')

host = 'localhost'
port = int(remoteConfig['DEFAULT']['port'])

print(port)

# ctx = SSL.Context(SSL.TLSv1_2_METHOD)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# ssock = SSL.Connection(ctx, sock)

sock.bind((host, port))
sock.listen(1)
clisock, addr = sock.accept()

# slanje adrese i porta
poslani_podaci = ('{}:{}'.format('localhost', 5000)).encode()
clisock.send(poslani_podaci)

# CITANJE DATOTEKE USERS-PASSWORD.CONF
usersConfig = configparser.ConfigParser()
usersConfig.read('users-passwords.conf')

users = []

for username in usersConfig['users-passwords']:
    password = usersConfig['users-passwords'][username]
    users.append((username, password))

for user in users:
    print(user)

# primanje korisnickog imena
podaci = clisock.recv(1024)
username_client = podaci.decode()
print(username_client)

# primanje zaporke
podaci = clisock.recv(1024)
password_client = podaci.decode()
print(password_client)

# LOGIN PROVJERA
login_success = False
for user in users:
    hashed_password = crypt.crypt(password_client, user[1])
    userdata_client = (username_client, hashed_password)
    if user == userdata_client:
        login_success = True

print(login_success)

# slanje odgovora
poslani_podaci = 'hvala'.encode()
clisock.send(poslani_podaci)

# primanje simetricnog kljuca
podaci = clisock.recv(1024)
ciphertext = podaci

print(podaci)

# citanje privatnog kljuca
config = configparser.ConfigParser()
config.read('remoteshd.conf')
private_key = bytes(config['DEFAULT']['key_prv'], encoding='utf-8')

private_key = serialization.load_pem_private_key(
    private_key,
    password=b'1234'
    )

symmetric_key_decrypted = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print(symmetric_key_decrypted)

f = Fernet(symmetric_key_decrypted)

podaci = clisock.recv(1024)
decrypted_message = f.decrypt(podaci)
print(decrypted_message.decode())


# config = configparser.ConfigParser()
# config.read('remoteshd.conf')

# key1 = config['aplikacija']['key1']
# key2 = config['aplikacija']['key2']
# port = config['aplikacija']['port']

# print(key1)
# print(key2)
# print(port)

clisock.close()
# ssock.shutdown()
sock.close()

# ctx = SSL.Context(SSL.TLSv1_2_METHOD)

# sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# ssock = SSL.Connection(ctx, sock)

# ssock.connect(('', 5230))

# odgovor = ssock.recv(8192)
# print(odgovor.decode())

# ssock.shutdown()
# sock.close()