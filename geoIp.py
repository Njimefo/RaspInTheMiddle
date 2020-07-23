"""
geoIp.py - Lesen von geographischen Daten aus der lokalen MaxMind-Datenbank

-> Beispiel zum Aufrufen:
geoIp.init('GeoLite2-City.mmdb')
geoIpGet = geoIp('8.8.8.8')
geoIpGet.getFromDb()
print(geoIpGet.country) 
print(geoIpGet.city)
print(geoIpGet.postal)
print(geoIpGet.latitude)
print(geoIpGet.longitude)
geoIp.close()

-> Lizenz für das benutzte "geoip2" Modul:
https://pypi.python.org/pypi/geoip2
Gregory Oschwald
Apache License, Version 2.0

-> Lizenz für die benutzten geoIP-Datenbank:
https://dev.maxmind.com/geoip/geoip2/geolite2/
MaxMind
Creative Commons Attribution-ShareAlike 4.0 International License
This product includes GeoLite2 data created by MaxMind, available from http://www.maxmind.com

-> 
"""

import geoip2.database  # importieren arin whois-library

global geoIpObj


class geoIp:

    def init(path):  # initialisieren geoip-datenbank, bestimmen ihren pfad
        global geoIpObj
        geoIpObj = geoip2.database.Reader(path)

    def __init__(self, ip):  # initialisieren datenbank-leser, lesen daten von datenbank anhand einer ip
        global geoIpObj
        self.geoIpReturn = geoIpObj.city(ip)

    def getFromDb(self):  # returnen den kompletten bekommenen block aus der datenbank, setzen objektvariablen
        self.all = self.geoIpReturn
        self.country = self.geoIpReturn.country.name
        self.city = self.geoIpReturn.city.name
        self.postal = self.geoIpReturn.postal.code
        self.latitude = self.geoIpReturn.location.latitude
        self.longitude = self.geoIpReturn.location.longitude
        return self.geoIpReturn

    def close():  # schliessen geoip-datenbank
        global geoIpObj
        geoIpObj.close()