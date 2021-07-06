#   ________________________________________________________________________________
#   MODULI
import os, time, sys, signal, threading, configparser, socket, crypt
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
from hmac import compare_digest as compare_hash


#   ________________________________________________________________________________
#   GLOBALNE VARIJABLE

#   koristi se za dohvat home adrese u funkciji cd, i funkciji kvadrat za ispis datoteke
kucni_dir = os.path.expanduser('~')

#   vrijednost od koje se oduzimaju kvadrati u funkciji kvadrat
broj = 33330330330320320320

#   pohranjuje trenutno vrijeme (vec formatirani oblik)
vrijeme = time.ctime()

#   instanciranje liste koja pamti sve naredbe u sesiji
povijest = []


#   ________________________________________________________________________________
#   SIGNALI

#   ignorira signal 3 i ispisuje obavijest korisniku
def upravljacQUIT(broj_signala, stog):
    print('Signal broj 3 je ignoriran.')
    return

#   ispisuje obavijest i prekida izvodjenje programa
def upravljacTERM(broj_signala, stog):
    print('Pristigao je signal broj 15. Program se zavrsava.')
    sys.exit()

#   signali koji su usmjereni na posebne upravljace
signal.signal(signal.SIGINT, signal.SIG_DFL)
signal.signal(signal.SIGQUIT, upravljacQUIT)
signal.signal(signal.SIGTERM, upravljacTERM)


#   ________________________________________________________________________________
#   DEFINICIJE

#   ispisuje odzivni znak
def ispisi_odziv():
    #   da varijable budu globalne ili in-function defined?
    op_sustav = os.uname()[0]
    korisnik = os.getlogin()
    direktorij = os.getcwd()
    return '({}::{}){} $ '.format(korisnik, op_sustav, direktorij)

#   provjerava unos naredbi
def izvrsi(naredba_lista):
    #   funkcija radi za prepoznavanje naredbi
    #   funkcijama se proslijedjuje korisnicki unos u obliku liste (naredba, parametar, argument...)
    if naredba_lista[0] == 'pwd': return pwd(naredba_lista)
    elif naredba_lista[0] == 'ps': return ps(naredba_lista)
    elif naredba_lista[0] == 'echo': return echo(naredba_lista)
    elif naredba_lista[0] == 'kill': return kill(naredba_lista)
    elif naredba_lista[0] == 'cd': return cd(naredba_lista)
    elif naredba_lista[0] == 'date': return date(naredba_lista)
    elif naredba_lista[0] == 'ls': return ls(naredba_lista)
    elif naredba_lista[0] == 'touch': return touch(naredba_lista)
    elif naredba_lista[0] == 'rm': return rm(naredba_lista)
    elif naredba_lista[0] == 'kvadrat': return kvadrat(naredba_lista)
    elif naredba_lista[0] == 'remoteshd': remoteshd()
    elif naredba_lista[0] == 'remotesh': remotesh()
    elif naredba_lista[0] in ('izlaz', 'odjava'): return izlaz()
    else:
        return 'Neprepoznata naredba.\n'

#   ispisuje apsolutnu adresu trenutnog direktorija ili obavjestava o krivom unosu
def pwd(lista):
    if len(lista) == 1:
        return os.getcwd() + '\n'
    else:
        return "Naredba ne prima parametre ni argumente.\n"

#   ispisuje PID trenutnog procesa ili obavjestava o krivom unosu
def ps(lista):
    if len(lista) == 1:
	    return str(os.getpid()) + '\n'
    else:
	    return "Nepostojeći parametar ili argument.\n"

#   ispisuje korisnicki string ili obavjestava o krivom unosu
def echo(lista):
    if len(lista) == 1:
        return "Naredba prima barem jedan argument.\n"
    else:
        to_print = ''
        for dat in lista[1:]:
            dat = dat.replace('"', '')
            dat = dat.replace("'", '')
            to_print += dat + ' ' 
        to_print += '\n'
        return to_print

#   obraduje signal ili obavjestava o krivom unosu
def kill(lista):
    if len(lista) == 1:
        return "Naredba prima točno jedan parametar: naziv signala ili njegov redni broj.\n"
    else:
        parametar = lista[1]
        #   postavljanje adekvatne vrijednosti signala na temelju korisnickog unosa/stringa
        if parametar == '-SIGINT' or parametar == '-INT' or parametar == '-2':
            signal = 2
        elif parametar == '-SIGQUIT' or parametar == '-QUIT' or parametar == '-3':
            signal = 3
        elif parametar == '-SIGTERM' or parametar == '-TERM' or parametar == '-15':
            signal = 15
        else:
            signal = int(parametar.strip('-'))
        try:
            #   pokusaj egzekucije signala
            os.kill(os.getpid(), signal)
        except:
            #   inace, ispis pogreske
            return 'Pogreška. Naredba prima točno jedan parametar, ID signala.\n'

#   mjenja direktorij ovisno o koristenom parametru
def cd(lista):
    #   izvrsava se ako nema parametara
    if len(lista) == 1:
        os.chdir(kucni_dir)
        return ''
    #   izvrsava se ako ima jedan parametar
    elif len(lista) == 2:
        #   radi se slice prva dva karaktera u parametru, za provjeru parametra
        param = lista[1][0:2]
        if param == '.':
            return ''
        elif param == '..':
            roditelj = os.path.join(os.getcwd(), os.pardir)
            os.chdir(roditelj)
            return ''
        elif param == './':
            #   ako je adresa nepostojeca, ispisuje se obavijest o pogresci
            try:
                odrediste = lista[1].strip('./')
                dublje = os.path.join(os.getcwd(), odrediste)
                os.chdir(dublje)
                return ''
            except:
                return 'Nepostojeća adresa.\n'
        elif lista[1][0:1] == '/':
            try:
                os.chdir(lista[1])
                return ''
            except:
                return 'Nepostojeća adresa.\n'
        else:
            return 'Nepostojeći parametar.\n'
    #   izvrsava se ako ima previse parametara
    else:
        return 'Dopušten je unos samo jednog parametra.\n'

#   ispisuje posebno formatirano vrijeme, u kratkom ili dugom obliku dana u tjednu
def date(lista):
    if len(lista) == 1:
        return time.strftime("%H<>%M<>%S %A %d./%m./%Y", time.localtime()) + '\n'
    elif len(lista) == 2 and lista[1] == '-w':
        return time.strftime("%H<>%M<>%S %a %d./%m./%Y", time.localtime()) + '\n'
    else:
        return "Naredba prima najviše jedan parametar (-w).\n"

#   ispisuje sadrzaj direktorija, ovisno o adresi na koju pokazujemo
def ls(lista):
    #   izvrsava se ukoliko nije zadan ni argument ni parametar
    if len(lista) == 1:
        sadrzaj = os.scandir()
        to_print = ''
        for dat in sadrzaj:
            #   ako datoteka nije sakrivena (pocinje sa '.'), ispisi podatke
            if not dat.name[0] == '.':
                to_print += dat.name + '\n'
        return to_print
    #   izvrsava se ukoliko je zadan samo argument -l, za dugi ispis trenutnog direktorija
    elif len(lista) == 2 and lista[1] == '-l':
        sadrzaj = os.scandir()
        to_print = ''
        #   ispis i formatiranje naziva podataka (sirina i poravnanje)
        to_print += '{: <20}{: >10}{: >10}{: >10}{: >10}{: >10}'.format('Name', 'Mode' , 'Nlinks', 'UID', 'GID', 'Size') + '\n'
        to_print += ('-' * 70) + '\n'
        for dat in sadrzaj:
            if not dat.name[0] == '.':
                info = dat.stat()
                #   (limitacija) ispis je uredan samo za datoteke duljine do 20 karaktera
                to_print += '{: <20}{: >10}{: >10}{: >10}{: >10}{: >10}'.format(dat.name, info.st_mode, info.st_nlink, info.st_uid, info.st_gid, info.st_size) + '\n'
        return to_print
    #   izvrsava se ukoliko je zadana relativna adresa direktorija
    elif len(lista) == 2 and lista[1][0:2] == './':
        #   ispituje se valjanost pristupa direktoriju
        try:
            odrediste = lista[1].strip('./')
            dublje = os.path.join(os.getcwd(), odrediste)
            sadrzaj = os.scandir(dublje)
            to_print = ''
            for dat in sadrzaj:
                #   ako datoteka nije sakrivena (pocinje sa '.'), ispisi podatke
                if not dat.name[0] == '.':
                    to_print += dat.name + '\n'
            return to_print
        #   inace baca obavijest o krivom pristupu
        except:
            return 'Nepostojeća adresa.\n'
    #   izvrsava se ukoliko je zadan dugi ispis direktorija na relativnoj adresi
    elif len(lista) == 3 and lista[1] == '-l' and lista[2][0:2] == './':
        try:
            odrediste = lista[2].strip('./')
            dublje = os.path.join(os.getcwd(), odrediste)
            sadrzaj = os.scandir(dublje)
            to_print = ''
            to_print += '{:<20}{:>10}{:>10}{:>10}{:>10}{:>10}'.format('Name', 'Mode' , 'Nlinks', 'UID', 'GID', 'Size') + '\n' 
            to_print += ('-' * 70) + '\n'
            for dat in sadrzaj:
                if not dat.name[0] == '.':
                    info = dat.stat()
                    to_print += '{: <20}{: >10}{: >10}{: >10}{: >10}{: >10}'.format(dat.name, info.st_mode, info.st_nlink, info.st_uid, info.st_gid, info.st_size) + '\n'
            return to_print
        except:
            return 'Nepostojeća adresa.\n'
    #   ispisuje pogresku ukoliko je uneseno previse argumenata, ili krivih
    else:
        return 'Naredba prima najviše jedan parametar (-l) i jedan argument (rel. adresu).\n'

#   stvara datoteku na adresi ukoliko ona ne postoji
def touch(lista):
    odrediste = lista[1]
    if os.path.isfile(odrediste):
        return 'Datoteka već postoji.\n'
    else:
        #   ako pristup ne uspijeva
        try:
            open(odrediste, 'w').close()
            return ''
        #   ispisuje se pogreska
        except:
            return 'Nepostojeća adresa.\n'

#   brise datoteku na adresi ukoliko ona tamo postoji
def rm(lista):
    odrediste = lista[1]
    if os.path.isfile(odrediste):
        os.remove(odrediste)
        return ''
    #   ispisuje pogresku ako je pristup datoteci nevaljan
    else:
        return 'Datoteka ne postoji.\n'

# serverska strana
def remoteshd():
    # citanje remoteshd.conf
    remoteConfig = configparser.ConfigParser()
    remoteConfig.read('remoteshd.conf')

    # čitanje vrata te postavljanje adrese za uspostavu konekcije
    host = 'localhost'
    port = int(remoteConfig['DEFAULT']['port'])
    address = (host, port)

    # otvaranje socketa na navedenoj adresi
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(address)
    sock.listen(1)
    clisock, cliaddr = sock.accept()

    print('Klijent pristiže sa {}:{}\n'.format(cliaddr[0], cliaddr[1]))

    # čitanje datoteke users-password.conf
    usersConfig = configparser.ConfigParser()
    usersConfig.read('users-passwords.conf')

    # lista sprema učitane/registrirane korisnike
    users = []

    # lista se puni učitanim korisnicima (touple)
    for username in usersConfig['users-passwords']:
        password = usersConfig['users-passwords'][username]
        users.append((username, password))

    # ispis registriranih korisnika
    print('Registrirani korisnici:')
    print('{:<15}{}'.format('usr', 'pwd'))
    print('{:<15}{}'.format('---', '---'))
    for user in users:
        print('{:<15}{}'.format(user[0], user[1]))
    print('')

    login_success = False
    while not login_success:
        # primanje korisnickog imena
        podaci = clisock.recv(1024)
        cliuser = podaci.decode()
        print('Uneseni korisnik: ' + cliuser)

        # primanje zaporke
        podaci = clisock.recv(1024)
        clipass = podaci.decode()
        print('Unesena zaporka: ' + clipass)

        # provjera hashiranih zaporki
        for user in users:
            hashes_match = compare_hash((crypt.crypt(clipass, user[1])), user[1])
            if user[0] == cliuser and hashes_match:
                login_success = True

        # ispis uspješnosti prijave
        print('Uspješna prijava.' if login_success else 'Nepostojeći korisnik.', end='\n\n')

        # slanje stanja uspješnosti prijave
        podaci = str(login_success).encode()
        clisock.send(podaci)

    # pamćenje trenutnog direktorija glavnog shella
    pocetni_direktorij = os.getcwd()

    # ostatak programa se odvija samo u slučaju uspješne prijave
    if login_success == True:
        # primanje simetričnog ključa
        podaci = clisock.recv(1024)
        symmetric_key_encrypted = podaci
        print(symmetric_key_encrypted)

        # citanje privatnog kljuca iz remoteshd.conf
        config = configparser.ConfigParser()
        config.read('remoteshd.conf')
        private_key = bytes(config['DEFAULT']['key_prv'], encoding='utf-8')

        # pretvaranje byte zapisa u objekt za dešifriranje
        private_key = serialization.load_pem_private_key(
            private_key,
            password=b'1234'
            )

        symmetric_key_decrypted = private_key.decrypt(
            symmetric_key_encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(symmetric_key_decrypted, end='\n\n')

        # stvaranje Fernet objekta za daljnje šifriranje
        f = Fernet(symmetric_key_decrypted)

        # glavna petlja izvođenja shell naredbi
        is_running = True
        while(is_running):
            # postavljanje odziva i slanje klijentu
            odziv = '(sh):' + ispisi_odziv()
            podaci = f.encrypt(odziv.encode())
            clisock.send(podaci)

            # primanje naredbe
            podaci = clisock.recv(1024)
            naredba_decrypted = f.decrypt(podaci)
            naredba = naredba_decrypted.decode()
                    
            # ispis podataka o primljenoj naredbi
            print(time.ctime())
            print('Primljena naredba: ' + naredba)
            print('Statusni kod: 0')

            # split-anje naredbe, izvršavanje i ispis rezultata
            naredba_split = naredba.split()
            rezultat = izvrsi(naredba_split)
            rezultat_str = str(rezultat)
            print('Izlaz naredbe:\n' + rezultat_str, end='\n')

            # slanje rezultata
            podaci = f.encrypt(rezultat_str.encode())
            clisock.send(podaci)

            # izlaz iz remote shell-a
            if rezultat == False:
                is_running = False

    # vraćanje na zapamćeni direktorij (glavnog shella)
    os.chdir(pocetni_direktorij)

    # zatvaranje konekcije
    clisock.close()
    sock.close()
    return ''

# klijentska strana
def remotesh():
    # postavljanje adrese na koju se vrši povezivanje
    host = 'localhost'
    port = 5000
    address = (host, port)

    # spajanje i ispis adrese
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(address)
    print('Povezan na {}:{}\n'.format(host, port))

    login_success = False
    while not login_success:
        # slanje korisnickog imena
        print('Korisnicko ime: ', end='')
        poruka = input()
        podaci = poruka.encode()
        sock.send(podaci)

        # slanje zaporke
        print('Zaporka: ', end='')
        poruka = input()
        podaci = poruka.encode()
        sock.send(podaci)

        # primanje i ispis poruke uspjeha/neuspjeha
        primljeni_podaci = sock.recv(1024)
        login_success_state = primljeni_podaci.decode()

        if login_success_state == 'True':
            login_success = True
        else:
            login_success = False

        print('Uspješna prijava.' if login_success else 'Nepostojeći korisnik.', end='\n\n')

    # ostatak programa se odvija samo u slučaju uspješne prijave
    if login_success:
        # generiranje simetričnog kljuca
        symmetric_key = Fernet.generate_key()
        f = Fernet(symmetric_key)
        print(symmetric_key)

        # čitanje javnog ključa za enkripciju
        config = configparser.ConfigParser()
        config.read('remoteshd.conf')
        public_key = bytes(config['DEFAULT']['key_pub'], encoding='utf-8')

        # pretvaranje ključa u objekt za enkripciju
        public_key = serialization.load_pem_public_key(
            public_key
            )
        print(public_key)

        # enkripcija javnim ključem i ispis ključa
        symmetric_key_encrypted = public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(symmetric_key_encrypted, end='\n\n')

        # slanje simetričnog ključa
        podaci = symmetric_key_encrypted
        sock.send(podaci)

        # ispis pozdravne poruke
        print('Pozdrav! ({})'.format(time.ctime()))

        # glavna petlja slanja i primanja rezultata naredbi
        is_running = True
        while (is_running):
            # primanje odziva za ispis
            odziv_encrypted = sock.recv(1024)
            odziv = f.decrypt(odziv_encrypted)
            print(odziv.decode(), end='')

            # input naredbe i slanje
            naredba = input()
            podaci = f.encrypt(naredba.encode())
            sock.send(podaci)

            # primanje rezultata
            rezultat_encrypted = sock.recv(1024)
            rezultat_encoded = f.decrypt(rezultat_encrypted)
            rezultat = rezultat_encoded.decode()

            # u slučaju primanja 'False' stringa, izlazimo iz petlje
            if rezultat == 'False':
                is_running = False
                rezultat = ''

            # ispis rezultata
            print(rezultat, end = '\n')

    # zatvaranje konekcije
    sock.close()
    return ''

# izlaz iz aplikacije
def izlaz():
    #   ispisuje sadrzaj liste povijest u datoteku .hist prije izlaza iz sesije
    povijest_ispis = open(kucni_dir + '/.hist', 'w')
    for stavka in povijest:
        povijest_ispis.write(stavka)
        povijest_ispis.write('\n')
    povijest_ispis.close()
    # šalje se False vrijednost koja signalizira prekidanje glavne petlje programa
    return False


#   ________________________________________________________________________________
#   NITI

#   postavljanje lokota i barijere
lokot = threading.Lock()
barijera = threading.Barrier(4)

#   funkcija koju pozivaju niti tokom izvrsavanja
def oduzmi_kvad(id, pocetak, kraj):
    #   postavlja se lokot za limitiranje pristupa varijabli 'broj'
    lokot.acquire()
    global broj
    medjuvrijed = open(kucni_dir + '/result.txt', 'a')
    for i in range(pocetak, kraj):
        broj -= i*i
        medjuvrijed.write(str(broj))
        medjuvrijed.write('\n')
    medjuvrijed.close()
    #   lokot se otpusta nakon izvrsavanja izracuna
    lokot.release()
    if id == 2:
        time.sleep(2)
    #   nit ide na cekanje drugih nakon svog izvrsavanja
    barijera.wait()
    if id == 2:
        print('Sve niti su izvrsile rad.\n')

#   funkcija koja pokrece niti i instancira datoteku result.txt u kucnom direktoriju
def kvadrat(lista):
    open(kucni_dir + '/result.txt', 'w').close()
    nit1.start()
    nit2.start()
    nit3.start()
    nit4.start()
    nit1.join()
    nit2.join()
    nit3.join()
    nit4.join()
    return ''

#   cetiri niti koje dijele resurs broj i izvrsavaju zadacu oduzimanja kvadrata
#   zadacu kvadriranja brojeva od 1 do 95959 dijele proslijedjujuci svoj pocetak i kraj u funkciju
nit1 = threading.Thread(target=oduzmi_kvad, args=(1, 1, 24000))
nit2 = threading.Thread(target=oduzmi_kvad, args=(2, 24000, 48000))
nit3 = threading.Thread(target=oduzmi_kvad, args=(3, 48000, 72000))
nit4 = threading.Thread(target=oduzmi_kvad, args=(4, 72000, 95960))


#   ________________________________________________________________________________
#   MAIN

#   ispis pozdravne poruke i trenutnog vremena
print('Pozdrav! ({})'.format(vrijeme))

#   glavna petlja
is_running = True
while (is_running):
    odziv = ispisi_odziv()
    print(odziv, end='')
    unos = input()
    unos_split = unos.split()
    #   ako je lista prazna, preskoci egzekuciju (kako se ne bi pristupalo indeksima kojih nema)
    if not unos_split:
        continue
    #   ako lista nije prazna, dodaj u .hist, provjeri postoji li definicija i izvrsi naredbu
    else:
        povijest.append(unos)
        rezultat = izvrsi(unos_split)
        # u slucaju izlaza, petlja se prekida
        if rezultat == False :
            is_running = False
            rezultat = ''
        elif rezultat == None:
            rezultat = ''
        else:
            print(rezultat)