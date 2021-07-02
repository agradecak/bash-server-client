
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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

sock.close()