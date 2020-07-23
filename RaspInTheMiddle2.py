import time
from datetime import datetime
import geoip2.database
from networkSniffer import *
import jsonpickle
from pcap import pcapSave
import os
from iptables import *
import sys
import subprocess
import uuid
from flask_socketio import SocketIO, emit
from flask import Flask, render_template, request, url_for, redirect, session, copy_current_request_context, request
from threading import Thread, Event
from time import sleep
import socket
import json
from collections import namedtuple
from cryptography.fernet import Fernet
from bluepy.btle import Scanner, DefaultDelegate, BTLEException

__author__ = 'slynn'

app = Flask(__name__)

app.config['SECRET_KEY'] = """MIICXAIBAAKBgQCRTJhtabKf04zemYIdjNvQ3HQnq4xyBDquGELWSsEFOcktUyMM
                              K36AzxCW7YSnMai5kQAvWP8stkvh1BpYyROCJHKT5Fbo9xh1YBkznHQ9RLGQLrIG
                              yTgJ1f9P/5DDAj/iv+B41XWYzZafA+DE2l9PKVjWoPDc9Y2tIHkBNbEQAQIDAQAB
                              AoGAIhgJBFNy+JHZUjpPD8QHqGCyWMSmNfLMGiHTPRlZZXKDxEDnzmk+S9dKmz+s
                              itbaMoDVvEZzyfgUoi7057R3AQ0yUo3F4wNkMBGLF4+/RExP7+Db/pmYlOZmuGjC
                              HiJRKL0HH81TXy+3K/UALesWCljPBBuCYw+XKi8f8O+KFMkCQQDfbqz2z5r1e4Hb
                              0Rw63bdHK551idF01ztbIuIr/kN5XBVxIPkqFGrkFdQeyYgHEyyKy5RIcBlitIdD
                              O/jScz4nAkEApnpmk6BlQfv7cfvUNmy8/+IZh68PLl6iWT137F4lCJXXqLYpmJ2I
                              jfARTzsUjS4lgHbewPBj61/CtXugBMTBlwJAQJW9aZqZMFyDLQdFIb71O51gMJml
                              8iBFCBMNTaox1uLHT+w4GfHM9CFbL4sRxvnD5lrygf3lWKLWdpjfU/X8AQJACSeq
                              BGxJpTtKNJZ4sRWBv0Cbzs5ds1sY6ndq5OC4gKRc27ZIy0++dq/BA+5nzuu+vDXN
                              Qib2F7eIaZqGzjxTuQJBALRDW4Qlfsszr6g2fTSIN1GhoyU7HivF3RYGOS5jM/d4
                              rQ0b5oSENeHnT7jEdwxoghLxmAq81lb46UOPY5RP/Xo="""

app.config['DEBUG'] = False

#NTB
#Transformiert die Flask App zu Socket Io Ap
_socketio = SocketIO(app)


thread = Thread()
thread_stop_event = Event()

global captureThreadFlag
captureThreadFlag =  0
global autoscrollCbChecked
global packets
packets = {}
global usersDatabase, ipRangesDatabse, ipAdressesDatabase
global selectedLine
selectedLine = 0
global  pcapCloseFlag
pcapCloseFlag = 0
global txt
txt = ""
global APP_ROOT
global pcap

APP_ROOT = os.path.dirname(os.path.abspath(__file__))


class BlockedIpAdress:
    def __init__(self, date, by, ipadress):
        self.Date = date
        self.By = by
        self.IpAdress = ipadress


class BlockedIpRange:
    def __init__(self, date, by, iprange):
        self.Date = date
        self.By = by
        self.IpRange = iprange


class BlockedIpAdressesDatabase:
    def __init__(self):
        databaseFile = open(os.path.join(APP_ROOT, "blockedIpAdresses.txt"), "r")
        lines = databaseFile.readlines()
        linesNr = len(lines)
        databaseFile.close()
        self.decodor = Decodor()
        if linesNr == 0:
            self.BlockedIpAdresses = []
        else:
            decryptedData = self.decodor.Decrypt(lines[0])
            self.BlockedIpAdresses = json.loads(decryptedData,
                                                object_hook=lambda d: namedtuple('BlockedIpAdress', d.keys())(
                                                    *d.values()))

    def addBlockedIpAdress(self, ip, by="Admin"):

        try:
            for _ip in self.BlockedIpAdresses:
                if _ip.IpAdress == ip.IpAdress:
                    return 1

            self.BlockedIpAdresses.append(ip)
            self.writeData()
            ipv4.blockIp(ip.IpAdress)
            return 1
        except Exception as error:
            return -1

    def removeBlockedIpAdress(self, ip):
        try:
            self.BlockedIpAdresses.remove(ip)
            self.writeData()
            ipv4.unblockIpRange(ip.IpAdress)
            return 1
        except Exception as error:
            return -1

    def writeData(self):
        jsonDtata = jsonpickle.encode(self.BlockedIpAdresses, unpicklable=False)
        encryptedData = self.decodor.Encrypt(jsonDtata)
        databaseFile = open(os.path.join(APP_ROOT, "blockedIpAdresses.txt"), "w")
        databaseFile.write(encryptedData.decode())
        databaseFile.close()

    def showAll(self):
        print(jsonpickle.encode(self.BlockedIpAdresses, unpicklable=False))


# NTB
# Klasse für Verwaltung von blockierten Ip-Ranges
class BlockedIpRangesDatabase:
    def __init__(self):
        databaseFile = open(os.path.join(APP_ROOT, "blockedIpRanges.txt"), "r")
        lines = databaseFile.readlines()
        linesNr = len(lines)
        databaseFile.close()
        self.decodor = Decodor()
        if linesNr == 0:
            self.BlockedIpRanges = []
        else:
            decryptedData = self.decodor.Decrypt(lines[0])
            self.BlockedIpRanges = json.loads(decryptedData,
                                              object_hook=lambda d: namedtuple('BlockedIpRange', d.keys())(*d.values()))

    # fügt einen neuen blcokierten Ip-Bereich
    def addBlockedIpRange(self, ipRange, by="Admin"):
        try:
            for _ipRange in self.BlockedIpRanges:
                if _ipRange.IpRange == ipRange.IpRange:
                    return 1

            self.BlockedIpRanges.append(ipRange)
            self.writeData()
            ipv4.blockIpRange(ipRange.IpRange)
            return 1
        except Exception as error:
            return -1

    # entfernt den angegebenen Ip-Bereich von blockierten Ip-Bereichen
    def removeBlockedIpRange(self, ipRange):
        try:
            self.BlockedIpRanges.remove(ipRange)
            self.writeData()
            ipv4.unblockIpRange(ipRange.IpRange)
            return 1
        except Exception as error:
            return -1

    # Schreibt die Daten in die Datei
    def writeData(self):
        jsonDtata = jsonpickle.encode(self.BlockedIpRanges, unpicklable=False)
        encryptedData = self.decodor.Encrypt(jsonDtata)
        databaseFile = open(os.path.join(APP_ROOT, "blockedIpRanges.txt"), "w")
        databaseFile.write(encryptedData.decode())
        databaseFile.close()

    def showAll(self):
        print(jsonpickle.encode(self.BlockedIpRanges, unpicklable=False))


# NTB
class User:

    def __init__(self, username, password, isAdmin=False):
        self.Username = username
        self.Password = password
        self.IsAdmin = isAdmin
        self.Id = None


# NTb
# Klasse für Verwaltung von Benutzern
class UsersDatabase:
    def __init__(self):
        databaseFile = open(os.path.join(APP_ROOT, "database.txt"), "r")
        lines = databaseFile.readlines()
        linesNr = len(lines)
        databaseFile.close()
        self.decodor = Decodor()
        if linesNr == 0:
            self.Users = []
        else:
            decryptedData = self.decodor.Decrypt(lines[0])
            self.Users = json.loads(decryptedData, object_hook=lambda d: namedtuple('User', d.keys())(*d.values()))

    # fügt einen neuen User ein
    def addUser(self, user):
        try:
            for _user in self.Users:
                if str(type(_user)) == '<class \'list\'>':
                    if user.Username == _user[3]:
                        return 0
                elif user.Username == _user.Username:
                    return 0

            self.Users.append(user)
            self.writeData()
            return 1
        except Exception as error:
            return -1

    # checkt ob der User das anagegebene Passwort hat
    def checkPassword(self, user):
        for _user in self.Users:
            if str(type(_user)) == '<class \'list\'>':
                if user.Username == _user[3] and user.Password == _user[2]:
                    return True
            elif user.Username == _user.Username and user.Password == _user.Password:
                return True
        return False

    # schreibt die Daten in die Datei
    def writeData(self):
        jsonDtata = jsonpickle.encode(self.Users, unpicklable=False)
        encryptedData = self.decodor.Encrypt(jsonDtata)
        databaseFile = open(os.path.join(APP_ROOT, "database.txt"), "w")
        databaseFile.write(encryptedData.decode())
        databaseFile.close()

    def showAll(self):
        print(jsonpickle.encode(self.Users, unpicklable=False))


# NTB
# Klasse für Verschlüsselung von Daten
class Decodor:

    def __init__(self):
        self.keyGenerator = KeyGenerator()
        self.keyGenerator.getKey()

    # verschlüsselt einen Text
    # der Schlüssel braucht nicht angegeben werden, denn der automatisch von der Keygenerator Klasse generiert wird
    def Encrypt(self, text):
        cipher_suite = Fernet(self.keyGenerator.Key)
        return cipher_suite.encrypt(text.encode())

    # entschlüsselt einen Text
    # der Schlüssel braucht nicht angegeben werden, denn der automatisch von der Keygenerator Klasse generiert wird
    def Decrypt(self, encrypted_text):
        cipher_suite = Fernet(self.keyGenerator.Key)
        return cipher_suite.decrypt(encrypted_text.encode()).decode()


# NTB
# Klasse für die automatische Generierung von einem Schlüssel ( zur Datenverschlüsselung)
class KeyGenerator:
    def getKey(self):
        keyFile = open(os.path.join(APP_ROOT, "key.txt"), "r")
        lines = keyFile.readlines()
        linesNr = len(lines)
        keyFile.close()
        if linesNr is 0:
            self.setKey()
        else:
            self.Key = lines[0].encode()

    # generiert einen Schlüssel
    def setKey(self):
        self.Key = Fernet.generate_key()
        keyFile = open(os.path.join(APP_ROOT, "key.txt"), "w")
        keyFile.write(self.Key.decode())
        keyFile.close()


# NTB
class EthDataToSave:
    def __init__(self, data, timestampSec, timestampMicroSec, id):
        self.Data = data
        self.TimestampSec = timestampSec
        self.TimestampMicroSec = timestampMicroSec
        self.Id = id


# NTB
class ethDataToSend:

    def __init__(self, _srcMac, _destMac, _type, _totalLength, _dataLength, _data, _completeText, _time):
        self.sourceMac = _srcMac
        self.destMac = _destMac
        self.type = _type
        self.totalLength = _totalLength
        self.dataLength = _dataLength
        self.Data = _data
        self.completeText = _completeText
        self.time = _time
        self.Id = None


# NTB
class ipv4ToSend:
    def __init__(self, _version, _headerLength, _serviceType, _totalLength, _idHex, _id, _timeToLive, _protocol,
                 _headerChecksum, _verifyChecksum, _verifiedChecksum,
                 _dfFlag, _mfFlag, _fragOffset, _sourceIp, _destIp, _data, _geoData, _srcHost, _destHost, _ispData):
        self.version = _version
        self.headerLength = _headerLength
        self.serviceType = _serviceType
        self.totalLength = _totalLength
        self.idHex = _idHex
        self.id = _id
        self.timeToLive = _timeToLive
        self.protocol = _protocol
        self.headerChecksum = _headerChecksum
        self.verifyChecksum = _verifyChecksum
        self.verifiedChecksum = _verifiedChecksum
        self.dfFlag = _dfFlag
        self.mfFlag = _mfFlag
        self.fragOffset = _fragOffset
        self.sourceIp = _sourceIp
        self.destIp = _destIp
        self.Data = _data
        self.geoData = _geoData
        self.ispData = _ispData
        self.srcHost = _srcHost
        self.destHost = _destHost


# NTB
class tcpSegmentToSend:
    def __init__(self, _sourcePort, _destPort, _seqNum, _ackNum, _window, _checksum, _verifyChecksum,
                 _verifiedChecksum, _cwrFlag, _eceFlag, _urgFlag, _urgPointer, _ackFlag, _pshFlag, _rstFlag,
                 _synFlag, _finFlag, _dataLength, data):
        self.sourcePort = _sourcePort
        self.destPort = _destPort
        self.seqNum = _seqNum
        self.ackNum = _ackNum
        self.window = _window
        self.checksum = _checksum
        self.verifyChecksum = _verifyChecksum
        self.verifiedChecksum = _verifiedChecksum
        self.cwrFlag = _cwrFlag
        self.eceFlag = _eceFlag
        self.urgPoint = _urgPointer
        self.ackFlag = _ackFlag
        self.pshFlag = _pshFlag
        self.rstFlag = _rstFlag
        self.synFlag = _synFlag
        self.finFlag = _finFlag
        self.dataLength = _dataLength
        self.Data = data


# NTB
class udpSegmentToSend:
    def __init__(self, _sourcePort, _destPort, _length, _checksum, _verifyChecksum, _verifiedChecksum, _data):
        self.sourcePort = _sourcePort
        self.destPort = _destPort
        self.length = _length
        self.checksum = _checksum
        self.verifyChecksum = _verifyChecksum
        self.verifiedChecksum = _verifiedChecksum
        self.Data = _data


# NTB
class icmpSegmentToSend:
    def __init__(self, _messageType, _code, _checksum, _verifyChecksum, _verifiedChecksum, _data):
        self.messageType = _messageType
        self.code = _code
        self.checksum = _checksum
        self.verifyChecksum = _verifyChecksum
        self.verifiedChecksum = _verifiedChecksum
        self.Data = _data


# NTB
class geoDataToSend:
    def __init__(self, _cityName, _postalCode, _latitude, _longitude):
        self.cityName = _cityName
        self.postalCode = _postalCode
        self.latitude = _latitude
        self.longitude = _longitude


# NTB
class ispDataToSend:
    def __init__(self, _autonomous_system_number, _autonomous_system_organization, _isp, _organization):
        self.autonomous_system_number = _autonomous_system_number
        self.autonomous_system_organization = _autonomous_system_organization
        self.isp = _isp
        self.organization = _organization


# NTB
# Klasse abgeleitet von Meta-Klasse Thread
# Thread Klasse für den Scan
class CaptureThread(Thread):
    def __init__(self):
        self.delay = 0.001
        super(CaptureThread, self).__init__()

    # NTB
    # startet den Scan-Vorgang
    def run(self):
        self.captureDo()

    # NTB
    # Führt den Scan-Vorgang
    def captureDo(self):
        global captureThreadFlag, autoscrollCbChecked, packets, pcap, pcapCloseFlag

        mainSocket = sniffer.init()  # initialisieren socket

        while True:

            if captureThreadFlag == 1:

                rawData, socketAdr = sniffer.getPacket(mainSocket)  # paket nehmen
                #print('Received Type ' +socketAdr[0])
                if socketAdr[0] == 'wlan0' or socketAdr[0] == 'wlp2s0' or socketAdr[0] == 'wlp3s0' :  # filtern netzwerkinterface
                    eth = ethernetFrame(rawData)
                    if eth.type == 8:  # only ipv4

                        # kalkulieren timestamp:
                        timestampSec, timestampMicroSec = map(int, str(time.time()).split(
                            '.'))  # nehmen unix-time und spalten diese nach sekunden und mikrosekunden

                        # formatieren mikrosekunden nach konventionen, max. 6 stellen
                        timestampMicroSecStr = str(timestampMicroSec)[:6]  # schneiden die ersten 6 ziffern ab
                        timestampMicroSecStr = timestampMicroSecStr.ljust(6,
                                                                          '0')  # füllen hinten mit nullen (falls zahl kleiner als 6 stellen)
                        timestampMicroSec = int(timestampMicroSecStr)  # konvertieren nach integer

                        # Generiert ein Id für das neue Paket
                        Id = uuid.uuid4()

                        ethDataToSave = EthDataToSave(rawData, timestampMicroSec, timestampMicroSec, str(Id))

                        # fügt Ethernet in Dictionnary packets mittels seines oben generierten Ids
                        packets.update({str(ethDataToSave.Id): ethDataToSave})

                        # Konvertiert die Raw-Daten(in Bytes) zu Klassenobjekten (in ethToSend)
                        toSendData = self.parseData(rawData, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), Id)

                        # konvertiert das Paket in Json-String
                        jsonData = jsonpickle.encode(toSendData, unpicklable=False)

                        # Print Daten (für Debugging notwendig)
                        print(jsonData)

                        # Sendet den Klienten das neue Paket
                        _socketio.emit('newpacket', {'packet': jsonData}, namespace='/packetTransfer')

                        # pausiert den Thread für die bei delay angegebene Zeit
                        sleep(self.delay)

            else:
                time.sleep(0.5)

    # beenden aufnahme der datenpakete
    def captureEnd(self):
        global captureThreadFlag, pcap
        if captureThreadFlag == 1:
            captureThreadFlag = 0  # flag beendet die aufnahme im aufnahme-thread

    # NTB
    # Konvertiert das Datenpacket in Klassen Objekt ethDataToSend
    def parseData(self, rawData, time, id) -> ethDataToSend:
        global tcp, icmp, ipv4, udp, packets, selectedLine, treeSelectLoadFlag, ipv4Obj, txt, dataToSend
        txt = ""

        eth = ethernetFrame(rawData)

        ipv4Obj = ipv4 = ipv4Packet(eth.data)

        if ipv4.protocol == 6:  # 6 = tcp

            tcp = tcpSegment(ipv4.data)
            hexData = convertToHexdump(tcp.data)

            # TCP Segement übergeben
            subData2ToSend = tcpSegmentToSend(tcp.sourcePort, tcp.destPort, tcp.seqNum, tcp.ackNum, tcp.window,
                                              tcp.checksum, tcp.verifyChecksum(),
                                              tcp.verifiedChecksum, tcp.cwrFlag, tcp.eceFlag, tcp.urgFlag,
                                              tcp.urgPointer, tcp.ackFlag, tcp.pshFlag, tcp.rstFlag,
                                              tcp.synFlag, tcp.finFlag, tcp.dataLength, str(hexData))

            txt1, geoData, ispData = self.getGeoAndIspData(ipv4.sourceIp, ipv4.destIp)

            # IPV4 Daten packen
            subData1ToSend = ipv4ToSend(ipv4.version, ipv4.headerLength, ipv4.serviceType, ipv4.totalLength, ipv4.idHex,
                                        ipv4.id, ipv4.timeToLive, ipv4.protocol, ipv4.headerChecksum,
                                        ipv4.verifyChecksum(), ipv4.verifiedChecksum,
                                        ipv4.dfFlag, ipv4.mfFlag, ipv4.fragOffset, ipv4.sourceIp, ipv4.destIp,
                                        subData2ToSend, geoData, socket.getfqdn(ipv4.sourceIp),
                                        socket.getfqdn(ipv4.destIp), ispData)

            # gesamte Daten packen
            dataToSend = ethDataToSend(eth.sourceMac, eth.destMac, eth.type, eth.totalLength, eth.dataLength,
                                       subData1ToSend,
                                       txt, time)

        elif ipv4.protocol == 17:  # 17 = udp
            udp = udpSegment(ipv4.data)
            hexData = convertToHexdump(udp.data)
            # UDP Segement übergeben
            subData2ToSend = udpSegmentToSend(udp.sourcePort, udp.destPort, udp.length, udp.checksum,
                                              udp.verifyChecksum(), udp.verifiedChecksum, str(hexData))
            txt1, geoData, ispData = self.getGeoAndIspData(ipv4.sourceIp, ipv4.destIp)
            txt += txt1
            # IPV4 Daten packen
            subData1ToSend = ipv4ToSend(ipv4.version, ipv4.headerLength, ipv4.serviceType, ipv4.totalLength, ipv4.idHex,
                                        ipv4.id, ipv4.timeToLive, ipv4.protocol, ipv4.headerChecksum,
                                        ipv4.verifyChecksum(), ipv4.verifiedChecksum,
                                        ipv4.dfFlag, ipv4.mfFlag, ipv4.fragOffset, ipv4.sourceIp, ipv4.destIp,
                                        subData2ToSend, geoData, socket.getfqdn(ipv4.sourceIp),
                                        socket.getfqdn(ipv4.destIp), ispData)

            # gesamte Daten packen
            dataToSend = ethDataToSend(eth.sourceMac, eth.destMac, eth.type, eth.totalLength, eth.dataLength,
                                       subData1ToSend,
                                       txt, time)

        elif ipv4.protocol == 1:  # 1 = icmp

            icmp = icmpSegment(ipv4.data)

            hexData = convertToHexdump(icmp.data)
            # ICMP Segement packen
            subData2ToSend = icmpSegmentToSend(icmp.messageType, icmp.code, icmp.checksum, icmp.verifyChecksum(),
                                               icmp.verifiedChecksum, str(hexData))
            txt1, geoData, ispData = self.getGeoAndIspData(ipv4.sourceIp, ipv4.destIp)

            # IPV4 Daten packen
            subData1ToSend = ipv4ToSend(ipv4.version, ipv4.headerLength, ipv4.serviceType, ipv4.totalLength, ipv4.idHex,
                                        ipv4.id, ipv4.timeToLive, ipv4.protocol, ipv4.headerChecksum,
                                        ipv4.verifyChecksum(), ipv4.verifiedChecksum,
                                        ipv4.dfFlag, ipv4.mfFlag, ipv4.fragOffset, ipv4.sourceIp, ipv4.destIp,
                                        subData2ToSend, geoData, socket.getfqdn(ipv4.sourceIp),
                                        socket.getfqdn(ipv4.destIp), ispData)

            # gesamte Daten packen
            dataToSend = ethDataToSend(eth.sourceMac, eth.destMac, eth.type, eth.totalLength, eth.dataLength,
                                       subData1ToSend,
                                       txt,
                                       time)
        else:
            dataToSend = None

        dataToSend.Id = id

        return dataToSend

    # NTB
    # checkt ob eine der übergebenen Adressen privat ist
    def checkPrivateIp(self, srcIp, destIp):
        lookupIp = ""
        sourcIp = srcIp[:7]
        destIp = destIp[:7]
        # überprüfen welche der source und destination addressen nicht die eigene ist
        if "192.168" in sourcIp and (not ("192.168" in destIp)):
            lookupIp = ipv4.destIp
        elif (not ("192.168" in sourcIp)) and "192.168" in destIp:
            lookupIp = ipv4.sourceIp
        return lookupIp

    # NTB
    # Holt ISP und Geo Daten von von lokaler und nicht online Datenbank
    def getGeoAndIspData(self, srcIp, destIp):

        lookupIp = self.checkPrivateIp(srcIp, destIp)

        if not lookupIp == "":
            txt1, geoData = self.getGeoData(lookupIp)
            txt2, ispData = self.getIspData(lookupIp)
            return txt1 + txt2, geoData, ispData
        else:
            return "\n\nGeo-Ip-Lookup : Local", geoDataToSend("-", "-", "0", "0"), ispDataToSend("-", "-", "-", "local")

    # NTB
    # Holt Geo-Daten von lokaler und nicht online Datenbank
    def getGeoData(self, ip):
        try:
            geodb = geoip2.database.Reader(
                os.path.join(os.path.dirname(__file__), 'static/databases/GeoLite2-City.mmdb'))
            geodbElement = geodb.city(ip)

            geoData = geoDataToSend(str(geodbElement.city.name), str(geodbElement.postal.code),
                                    str(geodbElement.location.latitude), str(geodbElement.location.longitude))
            txt = "# GEO-IP-Lookup Stadt Daten (Offline-Datenbank): " + ip
            txt += "\n\n\tStadt: " + geoData.cityName
            txt += "\n\tPostleitzahl: " + geoData.postalCode
            txt += "\n\tBreitengrad: " + geoData.latitude
            txt += "\n\tLängengrad: " + geoData.longitude
            txt += "\n\n"
            return txt, geoData
        except Exception as err:
            print(err.__cause__)
            return "# GEO-IP-Lookup Stadt Daten fehlgeschlagen. IP nicht gefunden?\n\n", geoDataToSend("not found",
                                                                                                       "not found", "0",
                                                                                                       "0")

    # NTB
    # Holt Isp-Daten von von lokaler und nicht online Datenbank
    def getIspData(self, ip):
        try:
            geodb = geoip2.database.Reader(
                os.path.join(os.path.dirname(__file__), 'static/databases/GeoIP2-ISP.mmdb'))
            geodbElement = geodb.isp(ip)
            ispData = ispDataToSend(str(geodbElement.autonomous_system_number),
                                    str(geodbElement.autonomous_system_organization), str(geodbElement.isp),
                                    str(geodbElement.organization))
            txt = "# GEO-IP-Lookup ISP Daten (Offline-Datenbank): " + ip
            txt += "\n\n\tAutonome Systemnummer: " + ispData.autonomous_system_number
            txt += "\n\tAutonome Systemorganisation: " + ispData.autonomous_system_organization
            txt += "\n\tISP: " + ispData.isp
            txt += "\n\tOrganisation: " + ispData.organization
            txt += "\n\n"
            return txt, ispData
        except Exception as err:
            # zum Debuggen
            print(err)
            return "# GEO-IP-Lookup ISP Daten fehlgeschlagen. IP nicht gefunden?\n\n", ispDataToSend("-1", "not found",
                                                                                                     "-1",
                                                                                                     "not found")


# NTB von Vorgängern modifiziert
# starten pcap-aufnahme
def pcapStart(name="capture.pcap", mode="wb"):
    global pcap, pcapCloseFlag
    pcapCloseFlag = 0
    pcap = pcapSave(os.path.join(APP_ROOT, name), mode)


# NTB von Vorgängern
# Schließt die Pcap Datei und endet das Speichern
def pcapClose():
    global pcap, pcapCloseFlag
    try:
        pcap.close()
        pcapCloseFlag = 1
    except:
        pass


# NTB
# Sendet die Temlate für Anzeigen des ScanVerlaufs (für nicht eingelogte)
@app.route('/')
def start():
    session.clear()
    return render_template("startpage.html")


# NTB
# Emöglicht ein Loggin
# Sendet die Template für Loggin
@app.route('/login', methods=['GET', 'POST'])
def login():
    global usersDatabase
    session.clear()
    error = ''
    try:
        if request.method == "POST":
            username = request.form['username']
            password = request.form["password"]
            user = User(username, password)

            if usersDatabase.checkPassword(user):
                session["user"] = jsonpickle.encode(user, unpicklable=False)

                return redirect(url_for('startLogged'))

            else:
                error = "Passwort oder Benutzername ungültig"
        return render_template('login.html', notification=error)

    except Exception as e:
        return render_template('login.html', notification="Ein Fehler ist beim Einloggen aufgetreten")


# NTB
# regitriert einen Benutzer
# Sendet die Template für eine Registrierung zurück
@app.route('/register', methods=['GET', 'POST'])
def register():
    global usersDatabase
    error = ''
    try:
        if request.method == "POST":
            username = request.form['username']
            password = request.form["userpassword"]
            adminpassword = request.form["adminpassword"]
            admin = User("Admin", adminpassword, True)
            if usersDatabase.checkPassword(admin):
                user = User(username, password)
                user.Id = len(usersDatabase.Users) + 1
                result = usersDatabase.addUser(user)
                if result == 1:
                    return "<h1> Der Benutzer wurde hinzugefügt. Wie machen Sie weiter?</h1><br>" \
                           "<h2><a href=\"/login\"> Zur Loginpage</a> </h2>" \
                           "<h2><a href=\"/\"> Zur Startpage für Gäste</a> </h2><br>"
                elif result == 0:
                    error = "Benutzer oder Benutzername bereits registriert"
                else:
                    error = "Ein oder mehrere Fehler sind aufgetreten"
            else:
                render_template('register.html', notification="Adminpasswort falsch")
        return render_template('register.html', notification=error)
    except Exception as e:
        return render_template('register.html', notification=str(e))


# NTB
# Sendet die Temlate für Anzeigen des ScanVerlaufs (für eingelogte)
@app.route('/user')
def startLogged():
    try:
        user = jsonpickle.decode(session["user"])
        return render_template('startpageLogged.html', user=user)
    except Exception as err:
        return "<h1> Nicht eingeloggt?? </h1><br>" \
               "<h2> Gehen Sie <a href=\"/login\"> hier</a> um sich einloggen zu können </h2>"


# NTB
# Blockiert erhaltene Ip-Adresse
@app.route('/iptables/ipBlocking', methods=['POST'])
def ipBlocking():
    global ipAdressesDatabase
    try:
        user = jsonpickle.decode(session["user"])
        if (user["Username"] == 'Admin'):
            JsonData = request.get_json()
            data = json.decode(JsonData)
            ipData = BlockedIpAdress(data['Data']['Date'], data['Data']['By'], data['Data']['IpAdress'])
            result = ipAdressesDatabase.addBlockedIpAdress(ipData)
            if result == 1:
                return "{\"Result\": 1; \"Message\":\"Aktion erfolgreich\"}"
            elif result == 0:
                return "{\"Result\": 1; \"Message\":\"Ip Adresse schon blockiert\"}"
            else:
                return "{\"Result\": -1; \"Message\":\"Ein oder mehrere Fehler sind aufgetreten\"}"

        else:
            return "{\"Result\": 0; \"Message\":\"Sie haben kein Recht auf solche Anfragen\"}"

    except Exception as err:
        return "{\"Result\": -1; \"Message\":\"Sie haben kein Recht auf solche Anfragen.\nBitte loggen Sie sich ein.\"}"


# NTB
# Blockiert erhaltenen Ip Bereich
@app.route('/iptables/ipRangeBlocking', methods=['POST'])
def ipRangeBlocking():
    global ipRangesDatabse
    try:
        user = jsonpickle.decode(session["user"])
        if (user["Username"] == 'Admin'):
            JsonData = request.get_json()
            data = json.decode(JsonData)
            ipRangeData = BlockedIpRange(data['Data']['Date'], data['Data']['By'], data['Data']['IpRange'])
            result = ipRangesDatabse.addBlockedIpRange(ipRangeData)
            if result == 1:
                return "{\"Result\": 1; \"Message\":\"Aktion erfolgreich\"}"
            elif result == 0:
                return "{\"Result\": 0; \"Message\":\"Ip Range schon blockiert\"}"
            else:
                return "{\"Result\": -1; \"Message\":\"Ein oder mehrere Fehler sind aufgetreten\"}"

        else:
            return "{\"Result\": 0; \"Message\":\"Sie haben kein Recht auf solche Anfragen\"}"

    except Exception as err:
        return "{\"Result\": -1; \"Message\":\"Sie haben kein Recht auf solche Anfragen.\nBitte loggen Sie sich ein.\"}"


# NTB
# Entblockiert die erhaltene Ip-Adresse
@app.route('/iptables/ipUnBlocking', methods=['POST'])
def ipUnBlocking():
    global ipAdressesDatabase
    try:
        user = jsonpickle.decode(session["user"])
        if (user["Username"] == 'Admin'):
            JsonData = request.get_json()
            data = json.decode(JsonData)
            ipData = BlockedIpAdress(data['Data']['Date'], data['Data']['By'], data['Data']['IpAdress'])
            result = ipAdressesDatabase.removeBlockedIpAdress(ipData)
            if result == 1:
                return "{\"Result\": 1; \"Message\":\"Aktion erfolgreich\"}"
            elif result == 0:
                return "{\"Result\": 0; \"Message\":\"Ip Adresse schon entblockiert\"}"
            else:
                return "{\"Result\": -1; \"Message\":\"Ein oder mehrere Fehler sind aufgetreten\"}"

        else:
            return "{\"Result\": 0; \"Message\":\"Sie haben kein Recht auf solche Anfragen\"}"

    except Exception as err:
        return "{\"Result\": -1; \"Message\":\"Sie haben kein Recht auf solche Anfragen.\nBitte loggen Sie sich ein.\"}"


# NTB
# Blockiert erhaltenen Ip Adresse Bereich
@app.route('/iptables/ipRangeUnBlocking', methods=['POST'])
def ipRangeUnBlocking():
    global ipRangesDatabse
    try:
        user = jsonpickle.decode(session["user"])
        if (user["Username"] == 'Admin'):
            JsonData = request.get_json()
            data = json.decode(JsonData)
            ipRangeData = BlockedIpRange(data['Data']['Date'], data['Data']['By'], data['Data']['IpRange'])
            result = ipRangesDatabse.removeBlockedIpRange(ipRangeData)
            if result == 1:
                return "{\"Result\": 1; \"Message\":\"Aktion erfolgreich\"}"
            elif result == 0:
                return "{\"Result\": 0; \"Message\":\"Ip Range schon entblockiert\"}"
            else:
                return "{\"Result\": -1; \"Message\":\"Ein oder mehrere Fehler sind aufgetreten\"}"

        else:
            return "{\"Result\": 0; \"Message\":\"Sie haben kein Recht auf solche Anfragen\"}"

    except Exception as err:
        return "{\"Result\": -1; \"Message\":\"Sie haben kein Recht auf solche Anfragen.\nBitte loggen Sie sich ein.\"}"


# NTB
# sendet die Template für Ip Tabellen zurück
@app.route('/iptables')
def iptables():
    try:
        user = jsonpickle.decode(session["user"])
        if (user["Username"] == 'Admin'):
            return render_template('iptable.html')
        else:
            return "<h1> Sie haben kein Zugriffrecht auf die Seite </h1><br>" \
                   "<h2> Gehen Sie <a href=\"/login\"> hier</a> um sich einloggen zu können </h2>"

    except Exception as err:
        return "<h1> Nicht eingeloggt?? </h1><br>" \
               "<h2> Gehen Sie <a href=\"/login\"> hier</a> um sich einloggen zu können </h2>"


class ScanDelegate(DefaultDelegate):
    def __init__(self):
        DefaultDelegate.__init__(self)


@app.route('/bluetoothle')
def bluetoothle():
    return """
    <!DOCTYPE html>
    <html>
        <head>
        </head>
        <body>
            <h3>Initialize a Bluetooth-LE scan.</h3>
            <form method="POST" action="/bluetoothle_scan">
                <div class="form-group">
                    Number of seconds to scan for: <input type="number" name="scanDur">
                </div>
                <input class="btn btn-primary" type="submit" value="submit">
            </form>
        </body>
    </html>
    """


@app.route('/bluetoothle_scan', methods=['GET', 'POST'])
def bluetoothle_scan():
    if request.method == 'POST':
        scanDur = request.form['scanDur']
        with open(os.path.join(APP_ROOT, 'manufacturers.list'), 'r') as f:
            manufacturers = f.readlines()
        manufacturers = [x.strip().split('|') for x in manufacturers]

        scanner = Scanner()
        try:
            devices = scanner.scan(float(scanDur))

            htmlReturn = '''
                <!DOCTYPE html>
                <html>
                    <head>
                        <style>
                            table, th, td {
                                border: 1px solid black;
                                border-collapse: collapse;
                            }
                        </style>
                    </head>
                    <body>
                        <h3>Scanresult:</h3>
                        <table style="width:100%">
                            <tr>
                                <th>RSSI</th>
                                <th>MAC</th>
                                <th>AddressType</th>
                                <th>ManufacturerID</th>
                                <th>ManufacturerName</th>
                            </tr>
                           '''
            for dev in devices:
                manID = ""
                manName = ""
                for (adtype, desc, value) in dev.getScanData():
                    if "manufacturer" in desc.lower():
                        manID = value
                        manCorrect = value[2:4] + value[0:2]
                        for man in manufacturers:
                            if man[0].lower() == manCorrect:
                                manName = man[1]
                                break
                htmlReturn += "<tr><td>" + str(dev.rssi) + "</td><td>" + str(dev.addr) + "</td><td>" + str(
                    dev.addrType) + "</td><td>" + str(manID) + "</td><td>" + str(manName) + "</td></tr>"
            htmlReturn += "</table>Go back to <a href=\"/bluetoothle\">/bluetoothle</a></body></html>"
            return htmlReturn
        except BTLEException as e:
            return '<!DOCTYPE html><html><body><h3>No BLE devices found within the given timeframe. Try again at <a href="/bluetoothle">/bluetoothle</a></h3></body></html>'
        except Exception as e:
            print(e)
            return '<!DOCTYPE html><html><body><h3>Scan failed. Likely received incomplete BLE-Data stack. Try again at <a href="/bluetoothle">/bluetoothle</a></h3></body></html>'

    return '<!DOCTYPE html><html><body><h3>This page must be prompted using the form at <a href="/bluetoothle">/bluetoothle</a></h3></body></html>'


# NTB
# CallBackMethode wenn ein Klient dem Raum packetTransfer beigetreten hat
@_socketio.on('connect', namespace='/packetTransfer')
def clientConnected():
    global thread, captureThreadFlag
    print('Client connected')
    print("Starting Thread")
    captureThreadFlag = 1
    thread = CaptureThread()
    thread.start()


# NTB
# Kovertiert den nicht formatierten String in Hex-formatierten String
# ZB:
# Von c9a3902dfe924619bfc51159da6d8c01 zu c9a3902d-fe92-4619-bfc5-1159da6d8c01
def regenerateHexString(data, format=[8, 4, 4, 4, 12]):
    resultStr = ''
    try:
        for position in format:
            resultStr += data[0:position] + '-'
            if not len(data) == 0:
                data = data[position:None]

        return resultStr[0:len(resultStr) - 1]
    except:
        return None


# NTB
# Gibt an, welchen Status der aktuelle User hat
# Gast = -1
# normaler User = 0
# admin = 1
@app.route('/user/checkUser')
def checkUser():
    try:
        user = jsonpickle.decode(session["user"])
        if (user["Username"] == 'Admin'):
            return "{Result : 1}"
        else:
            return "{Result : 0}"

    except Exception as err:
        return "{Result : -1}"


# NTB
# speichert Pakete mithilfe gesendeter Ids
@app.route('/user/packetTransfer/dataSave', methods=['POST'])
def Savedata():
    global pcap, packets
    try:
        user = jsonpickle.decode(session["user"])
        if not (user["Username"] == 'Admin'):
            return "{Result: false, Executed: false, Message : \"You have no permission to execute this action\"}"
    except Exception as error:
        "{Result: false, Executed: false, Message : \"Please log in\"}"

    fileName = str(datetime.now().strftime('%Y_%m_%d_%H_%M') + ".pcap")
    filePath = os.path.join(APP_ROOT, fileName)
    mode = 'wb';
    if not os.path.isfile(filePath):
        mode = 'xb'
    pcapStart(filePath, mode)
    try:
        message = "Packets have been saved successfully"
        data = request.get_json()
        if not data:
            return "{Result: true, Executed: false, Message : \"There are no Json-Data passed\"}"
        for _data in data:
            hexData = regenerateHexString(_data['hex'])
            if (hexData in packets):
                rawData = packets[hexData]
                pcap.writePacket(rawData, True)

            else:
                message = "One or many packets could not be saved"

        pcapClose()
    except Exception as error:
        return "{Result: false, Executed: false, Message : \"One or many errors occured while processing your request\"}"

    return "{Result: true, Executed: true, Message : \"" + message + "\"}"


# NTB
# CallBack Methode wenn die Verbindung mit dem Klienten für Ip-Blockierung hergestellt wurde
# sendet an den Klienten alle bisher gespeicherten blockierten Ip-Adressen und Ranges
@_socketio.on('connect', namespace='/ipBlocking')
def clientConnectedIpBocking():
    global ipRangesDatabse, ipAdressesDatabase
    ipRangesDatabse = BlockedIpRangesDatabase()
    ipAdressesDatabase = BlockedIpAdressesDatabase()
    print('Client connected on Ip bocking page')
    ipRangesDatabseJson = jsonpickle.encode(ipRangesDatabse, unpicklable=False)
    ipAdressesDatabaseJson = jsonpickle.encode(ipAdressesDatabase, unpicklable=False)
    _socketio.emit('ipAdresses', {'ipAdresses': ipAdressesDatabaseJson}, namespace='/ipBlocking')
    _socketio.emit('ipRanges', {'ipRanges': ipRangesDatabseJson}, namespace='/ipBlocking')


# NTB
# CallBack Methode wenn die Verbindung mit dem Klienten für Ip-Blockierung unterbrochen wurde
@_socketio.on('disconnect', namespace='/ipBlocking')
def clientDisconnectedIpBocking():
    print('Client disconnected from Ip bocking page')


# NTB
# CallBack Methode wenn die Verbindung mit dem Klienten für Pakete Capture unterbrochen wurde
# endet den Capture-Thread
@_socketio.on('disconnect', namespace='/packetTransfer')
def clientDisconnected():
    global captureThreadFlag, thread
    captureThreadFlag = 0
    thread = None
    print('Client disconnected')


# NTB
# Starten des Programms
# Initialisierung der Datenbank für Benutzer-Verwaltung
if __name__ == '__main__':
    global usersDatabase
    usersDatabase = UsersDatabase()
    app.run()
