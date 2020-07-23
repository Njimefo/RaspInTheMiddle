"""
whoIs.py - Schicken und Empfangen von WHOIS-LOOKUPS

-> Beispiel zum Aufrufen:
whoIs_ = whoIs("8.8.8.8")
whoIs_.lookup()
print(whoIs_.getResponse())

-> Lizenz für das benutzte "ipwhois" Modul:
https://pypi.python.org/pypi/ipwhois
Copyright (c) 2013-2017 Philip Hane
All rights reserved.

-> Autor: Jean Chouameni
"""

from ipwhois import IPWhois #importieren arin whois-library

global whoIsReturn

class whoIs:

    def __init__(self, ip): #initialisieren whois auf einer ip
        self.whoIsObj = IPWhois(ip)

    def lookup(self): #stellen request an whois-server
        global whoIsReturn
        whoIsReturn = self.whoIsObj.lookup_whois(inc_nir = True)

    def getResponse(self):
        global whoIsReturn
        return whoIsReturn #returnen antwort von whois-servern (als dict)

    def getResponseNets(self):
        global whoIsReturn
        return whoIsReturn.get('nets') #returnen nur die elternnetzwerkte

    def getResponseNir(self):
        global whoIsReturn
        return whoIsReturn.get('nir') #returnen zusätzliche nir-informationen
#...
