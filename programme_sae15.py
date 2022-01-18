# -*- coding: utf-8 -*-
"""
Spyder Editor

This is a temporary script file.
"""
import os
import numpy as np

try:
    with open("wireshark.txt", encoding="utf8") as fh:
        res=fh.read()
except:
    print("Le fichier n'existe pas %s", os.path.abspath("wireshark.txt"))

ress=res.split('\n')
SYN ="[S],"
POUSSER = "[P.],"
RST = "[R],"
ip={}

for event in ress:
    if event.startswith('11:42'):
        texte=event.split(" ")
        if texte[5] == "Flags":
            evenement='temps : '+texte[0]+' Adresse Ip source : '+texte[2]+' Adresse IP destinataire : '+texte[4]+' flag : '+texte[6]
            if texte[6] == SYN:
                evenement_3 = ' '
                evenement_2 = 'Numéro de séquence : '+texte[8]+' Taille de la fenêtre : '+texte[10]+' Longueur du paquet : '+texte[12]
            if texte[6] == POUSSER:
                evenement_3 = ' '
                evenement_2 = 'Numéro de séquence : '+texte[8]+' Numéro accusé de réception : '+texte[10]
            if texte[6] == "[.],":
                evenement_2 = 'Numéro accusé de réception : '+texte[8]+' Taille de la fenêtre : '+texte[10]
                evenement_3 = ' Longueur du paquet : '+texte[12]
            if texte[6] == "[S.],":
                evenement_2 = 'Numéro de séquence : '+texte[8]+' Numéro accusé de réception : '+texte[10]+' Taille de la fenêtre : '+texte[12]
            #print(evenement+evenement_2+evenement_3)
            #print("PD")
            ipv4=texte[2].split('.')
            print("Port : ",ipv4[-1])
            del ipv4[-1]
            stripv4 = ".".join(ipv4)
            print(" Adresse IP : ",stripv4)
            try:
                ip[stripv4]
            except KeyError:
                ip[stripv4]=1
            else:
                ip[stripv4]+=1
                
print(sorted(ip.items(), key=lambda item: item[1]))
            
fh.close()