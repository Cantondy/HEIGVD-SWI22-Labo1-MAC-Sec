# Auteurs    : Dylan Canton & Christian Zaccaria
# Date       : 29.03.2022
# Descriptif : Script permettant liker une STA à un AP
# Entrée     : script5_linkApSta.py -i <INTERFACE> 

from scapy.all import *
import argparse

BROADCAST = "ff:ff:ff:ff:ff:ff"
list_sta_ap = []

# Param nécessaire (à remplir) permettant de lancer l'attaque
parser = argparse.ArgumentParser(prog="Link AP-STA", description="Search STA and link to AP witch is connected")

parser.add_argument("-i", "--Interface", required=True, help="Interface who send attack")
tab_args = parser.parse_args()

# Check les STA qui sont reliées à un AP
def link_sta_ap(pkt):
    # Paquets uniquement de type 2 (permettent de confirmer le lien entre une STA et AP)
    if pkt.type == 2:
        # Check que l'on diffuse pas vers un broadcast (mais bien d'un AP vers STA / STA vers AP)
        if pkt.addr1 != BROADCAST and pkt.addr2 != BROADCAST and pkt.addr3 is not None:
            # On check que la première adresse est la STA et ensuite l'AP, sinon on modifie
            if pkt.addr1 != pkt.addr3:
                sta_ap = (pkt.addr1, pkt.addr3)
            else:
                sta_ap = (pkt.addr2, pkt.addr3)
            
            # Si le lien STA-AP n'est pas déja connu, on l'ajoute et affiche
            if sta_ap not in list_sta_ap:
                list_sta_ap.append(sta_ap)
                print(sta_ap[0]+" \t\t "+sta_ap[1])


print("\nSTA \t\t\t\t AP")
sniff(iface=tab_args.Interface, prn=link_sta_ap)

