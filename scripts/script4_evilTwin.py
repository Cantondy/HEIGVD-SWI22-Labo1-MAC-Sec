# Auteurs    : Dylan Canton & Christian Zaccaria
# Date       : 24.03.2022
# Descriptif : Script permettant de detecter une STA cherchant un SSID défini et de proposer un evil Twin
# Entrée     : script4_evilTwin.py -n <NAME_SSID> -i <INTERFACE>
# Source     : http://www.nicola-spanti.info/fr/documents/tutorials/computing/programming/python/scapy/search-ssid-with-probe-request.html

from scapy.all import *
from sys       import argv
from os.path   import isfile
import argparse

# Param nécessaire (à remplir) permettant de lancer le scan
parser = argparse.ArgumentParser(prog="Scapy SSID finder", description="SSID scan in prob request")
parser.add_argument("-i", "--Interface", required=True, help="Interface to scan")
tab_args = parser.parse_args()
parser.add_argument("-s", "--SSID", required=True, help="Resarched SSID")

# SSID à trouver
target_ssid = tab_args.NameSSID
# Interface à utiliser pour le scan 
interface_to_check = tab_args.Interface

# Cherche un SSIF correspondant
def find_ssid(pkt):
    if Dot11ProbeResp in pkt and Dot11Elt in pkt[Dot11ProbeResp]:
        pkt = pkt[Dot11ProbeResp]
        pkt = pkt[Dot11Elt]
        if packet.ID == 0: # SSID
            if packet.info == target_ssid:
                evil_twin_attack()


# Propose de lancer une attaque evil twin si un SSID correspondant est trouvé
def evil_twin_attack():
    enable_attack = input("SSID : " + target_ssid + "trouvé, voulez-vous lancer une evil twin attack ? (y/n)")
    if enable_attack == "y":
        # Lancement de l'attaque evil twin



# On sniff le réseau sur l'interface choisie
sniff(iface=interface_to_check, prn=find_ssid, timeout=30)
