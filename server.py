from OpenSSL import SSL
from hmac import compare_digest as compare_hash
import configparser, socket, crypt

remoteConfig = configparser.ConfigParser()
remoteConfig.read('remoteshd.conf')

host = 'localhost'
port = int(remoteConfig['aplikacija']['port'])

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