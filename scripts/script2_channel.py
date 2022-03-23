# Auteurs    : Dylan Canton & Christian Zaccaria
# Date       : 23.03.2022
# Descriptif : Script permettant de récupérer les SSID et proposer à l'utilisateur d'en choisir un
#              pour forger un beacon similaire (différence de channel de 6 canaux)
# Source     : https://pypi.org/project/texttable/
#              https://www.thepythoncode.com/article/building-wifi-scanner-in-python-scapy


from scapy.all import *
import argparse
import texttable as text_t

bssid_list = []
pkt_list = []
ap_list = []

# Affichage des informations sous forme de tableau
def display_texttable(list):
    table = text_t.Texttable()
    table.set_deco(text_t.Texttable.HEADER)
    table.set_cols_dtype(['i','t','t','t','t']) 
    table.set_cols_align(["l", "l", "l", "l", "l"])
    table.add_row(["N°", "BSSID", "SSID", "Channel", "Strength"])

    i = 0
    for info in list:
        i += 1
        table.add_row([i, info[0], info[1], info[2], info[3]])
    print(table.draw())

# Recherche d'un paquet Beacon afin de pouvoir extraire les informations nécessaires
def SSID_finder(pkt):
    #check que la trame est de type "beacon"
    if pkt.haslayer(Dot11Beacon):
        #type doit être 0 et subtype 8 obligatoirement
        if pkt.type == 0 and pkt.subtype == 8:
            #check si on a déjà checker déjà le bssid (autrement on fait rien)
            if pkt.getlayer(Dot11).addr2 not in bssid_list:
                ssid = pkt.getlayer(Dot11Elt).info.decode("utf-8")
                #check si pas un réseau caché
                if ssid == '':
                    ssid = "Masked Network"

                #recupération de la puissance et du canal
                try:
                    #puissance émise
                    radiotap = pkt.getlayer(RadioTap)
                    rssi = radiotap.dBm_AntSignal
                    #canal d'émission
                    channel = pkt[Dot11Elt][2].info
                    channel = int.from_bytes(channel, byteorder='big')
                #si on recupère rien, on fixe une valeur
                except:
                    rssi = "unknown"
                    channel = "unknown"

                #on ajoute dans les informations trouvés dans les listes
                bssid_list.append(pkt.getlayer(Dot11).addr2)
                pkt_list.append(pkt)
                ap_list.append([pkt.getlayer(Dot11).addr2, ssid, channel, rssi])

            
interface_to_check = input("Nom de l'interface : ")
print("Interface selectionnée : " + interface_to_check)
sniff(iface=interface_to_check , prn=SSID_finder, timeout=10)
display_texttable(ap_list)
