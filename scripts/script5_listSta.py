# Auteurs    : Dylan Canton & Christian Zaccaria
# Date       : 29.03.2022
# Descriptif : Script permettant lister toutes les STA qui recherchent un SSID donné
# Entrée     : script5_listSta.py -i <INTERFACE> -s <SSID>

from scapy.all import *
import argparse

list_STA = []

# Param nécessaire (à remplir) permettant de lancer l'attaque
parser = argparse.ArgumentParser(prog="List STA", description="List STA who research SSID")

parser.add_argument("-i", "--Interface", required=True, help="Interface who send attack")
parser.add_argument("-s", "--SSID", required=True, help="Resarched SSID")
tab_args = parser.parse_args()

# Recherche des paquets probe ayant un SSID défini
def sta_finder(pkt):
    # Le paquet doit être un probe + être le SSID que l'on cherche + ne pas faire déjà partie de la liste (ne liste pas 2 fois le même)
    if pkt.type == 0 and pkt.subtype == 4 and tab_args.SSID == pkt.info.decode() and pkt.addr2 not in list_STA:
            list_STA.append(pkt.addr2)
            print(pkt.addr2)


print("List of stations who search SSID : " + tab_args.SSID + "\n")
sniff(iface=tab_args.Interface, prn=sta_finder)
