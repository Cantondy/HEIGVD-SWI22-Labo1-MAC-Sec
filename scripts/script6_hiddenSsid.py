# Auteurs    : Dylan Canton & Christian Zaccaria
# Date       : 29.03.2022
# Descriptif : Script permettant de reveler les SSID cachés
# Entrée     : script6_hiddenSsid.py -i <INTERFACE> 
# Source     : https://www.acrylicwifi.com/en/blog/hidden-ssid-wifi-how-to-know-name-of-network-without-ssid/
#              https://books.google.ch/books?id=FEBPDwAAQBAJ&pg=PA106&lpg=PA106&dq=%22python%22+scapy+expose+ssid+hidden&source=bl&ots=UgQwo3kNkT&sig=ACfU3U2O_yhFzZb5vhWnMfTBLK3peIuKzg&hl=fr&sa=X&ved=2ahUKEwiQ_7qI4JToAhUjwsQBHd8NBrkQ6AEwCHoECAoQAQ#v=onepage&q=%22python%22%20scapy%20expose%20ssid%20hidden&f=false

from scapy.all import *
import argparse
import texttable as text_t

ssid_hidden = dict()

# Param nécessaire (à remplir) permettant de lancer l'attaque
parser = argparse.ArgumentParser(prog="Hidden SSID", description="Find all SSID hidden")

parser.add_argument("-i", "--Interface", required=True, help="Interface who send attack")
tab_args = parser.parse_args()

conf.verb = 0

# Affichage des informations sous forme de tableau
def display_texttable(list):
    table = text_t.Texttable()
    table.set_deco(text_t.Texttable.HEADER)
    table.set_cols_dtype(['i','t','t']) 
    table.set_cols_align(["l", "l", "l"])
    table.add_row(["No", "BSSID", "SSID"])

    i = 0
    for key, value in ssid_hidden.items():
        i += 1
        table.add_row([i, key, value])
    print(table.draw())

#Recheche des SSID cachés (trouve le nom si des probes response sont envoyés)
def find_ssid(pkt):
    if pkt.haslayer(Dot11Elt):
        #Récupération du SSID (on remplace par rien les caractères \000)
        ssid = pkt.info.decode().replace("\000","")
        #Récupération du bssid
        bssid= pkt[Dot11].addr3
        #Si c'est une beacon frame --> ssid caché (besoin d'une probe response pour connaitre l'ssid)
        if pkt.haslayer(Dot11Beacon) and bssid not in ssid_hidden.keys() and ssid == "":
            ssid_hidden[bssid] = "SSID hidden"
        #Si c'est une probe response, on peut découvrir l'ssid
        elif (pkt.type == 0 and pkt.subtype == 5) and bssid in ssid_hidden.keys():
            ssid_hidden[bssid] = ssid

sniff(iface=tab_args.Interface, prn=find_ssid, timeout=20)
display_texttable(ssid_hidden)