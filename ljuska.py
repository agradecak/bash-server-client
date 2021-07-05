#   ________________________________________________________________________________
#   MODULI
import os
import time
import sys
import signal
import threading


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
    print('({}::{}){} $ '.format(korisnik, op_sustav, direktorij), end='')

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
    elif naredba_lista[0] == 'remoteshd': return remoteshd(naredba_lista)
    elif naredba_lista[0] == 'remotesh': return remotesh(naredba_lista)
    elif naredba_lista[0] == 'izlaz' or naredba_lista[0] == 'odjava': return izlaz()
    else:
        return 'Neprepoznata naredba.'

#   ispisuje apsolutnu adresu trenutnog direktorija ili obavjestava o krivom unosu
def pwd(lista):
    if len(lista) == 1:
        return os.getcwd()
    else:
        return "Naredba ne prima parametre ni argumente."

#   ispisuje PID trenutnog procesa ili obavjestava o krivom unosu
def ps(lista):
    if len(lista) == 1:
	    return os.getpid()
    else:
	    return "Nepostojeci parametar ili argument."

#   ispisuje korisnicki string ili obavjestava o krivom unosu
def echo(lista):
    if len(lista) == 1:
        return "Naredba prima barem jedan argument."
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
        return "Naredba prima tocno jedan parametar: naziv signala ili njegov redni broj."
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
            return 'Pogreska. Naredba prima tocno jedan parametar, ID signala.'

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
                return 'Nepostojeca adresa.'
        elif lista[1][0:1] == '/':
            try:
                os.chdir(lista[1])
                return ''
            except:
                return 'Nepostojeca adresa.'
        else:
            return 'Nepostojeci parametar.'
    #   izvrsava se ako ima previse parametara
    else:
        return 'Dopusten je unos samo jednog parametra.'

#   ispisuje posebno formatirano vrijeme, u kratkom ili dugom obliku dana u tjednu
def date(lista):
    if len(lista) == 1:
        return time.strftime("%H<>%M<>%S %A %d./%m./%Y", time.localtime())
    elif len(lista) == 2 and lista[1] == '-w':
        return time.strftime("%H<>%M<>%S %a %d./%m./%Y", time.localtime())
    else:
        return "Naredba prima najvise jedan parametar (-w)."

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
            return 'Nepostojeca adresa.'
    #   izvrsava se ukoliko je zadan dugi ispis direktorija na relativnoj adresi
    elif len(lista) == 3 and lista[1] == '-l' and lista[2][0:2] == './':
        try:
            odrediste = lista[2].strip('./')
            dublje = os.path.join(os.getcwd(), odrediste)
            sadrzaj = os.scandir(dublje)
            to_print = ''
            to_print += '{: <20}{: >10}{: >10}{: >10}{: >10}{: >10}'.format('Name', 'Mode' , 'Nlinks', 'UID', 'GID', 'Size') + '\n' 
            to_print += ('-' * 70) + '\n'
            for dat in sadrzaj:
                if not dat.name[0] == '.':
                    info = dat.stat()
                    to_print += '{: <20}{: >10}{: >10}{: >10}{: >10}{: >10}'.format(dat.name, info.st_mode, info.st_nlink, info.st_uid, info.st_gid, info.st_size) + '\n'
            return to_print
        except:
            return 'Nepostojeca adresa.'
    #   ispisuje pogresku ukoliko je uneseno previse argumenata, ili krivih
    else:
        return 'Naredba prima najvise jedan parametar (-l) i jedan argument (rel. adresu).'

#   stvara datoteku na adresi ukoliko ona ne postoji
def touch(lista):
    odrediste = lista[1]
    if os.path.isfile(odrediste):
        return 'Datoteka vec postoji.'
    else:
        #   ako pristup ne uspijeva
        try:
            open(odrediste, 'w').close()
            return ''
        #   ispisuje se pogreska
        except:
            return 'Nepostojeca adresa.'

#   brise datoteku na adresi ukoliko ona tamo postoji
def rm(lista):
    odrediste = lista[1]
    if os.path.isfile(odrediste):
        os.remove(odrediste)
        return ''
    #   ispisuje pogresku ako je pristup datoteci nevaljan
    else:
        return 'Datoteka ne postoji.'

def remoteshd():
    return


def remotesh():

    return

# izlaz iz aplikacije slanjem False vrijednosti koja prekida glavnu petlju
def izlaz():
    #   ispisuje sadrzaj liste povijest u datoteku .hist prije izlaza iz sesije
    povijest_ispis = open(kucni_dir + '/.hist', 'w')
    for stavka in povijest:
        povijest_ispis.write(stavka)
        povijest_ispis.write('\n')
    povijest_ispis.close()
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
        print('Sve niti su izvrsile rad.')

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
    ispisi_odziv()
    unos = input()
    unos_split = unos.split()
    #   ako je lista prazna, preskoci egzekuciju (kako se ne bi pristupalo indeksima kojih nema)
    if not unos_split:
        continue
    #   ako lista nije prazna, dodaj u .hist, provjeri postoji li definicija i izvrsi naredbu
    else:
        povijest.append(unos)
        rezultat = izvrsi(unos_split)
        if rezultat == False :
            is_running = False
            rezultat = ''
        print(rezultat)


# while (True)
#     klijent
#         while (True):
#             ispisi_odziv()
#             unos = input()
#             podaci = unos.encrypt()
#             send(podaci)

#             recv(1024)

#     server
#         recv(1024)

#         unos_split = unos.split()
#         podaci = ''
#         if not unos_split:
#             continue
#         else:
#             povijest.append(unos)
#             podaci = izvrsi(unos_split)

#         send(podaci)