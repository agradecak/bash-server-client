import configparser, socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

address = 'localhost'
port = 5000

sock.bind((address, port))
sock.listen(1)
clisock, addr = sock.accept()

# slanje adrese i porta
poslani_podaci = ('{}:{}'.format(address, port)).encode()
clisock.send(poslani_podaci)

# primanje korisnickog imena
podaci = clisock.recv(1024)
primljeno = podaci.decode()
print(primljeno)

# primanje zaporke
podaci = clisock.recv(1024)
primljeno = podaci.decode()
print(primljeno)

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
sock.close()

# ctx = SSL.Context(SSL.TLSv1_2_METHOD)

# sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# ssock = SSL.Connection(ctx, sock)

# ssock.connect(('', 5230))

# odgovor = ssock.recv(8192)
# print(odgovor.decode())

# ssock.shutdown()
# sock.close()