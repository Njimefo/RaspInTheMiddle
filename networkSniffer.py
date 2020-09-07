# -*- coding: utf-8 -*-
"""
# networkSniffer.py : Netzwerkschnüffler (Modul)

# Beschreibung: Fängt den IPv4-Netzwerkverkehr auf, parst die
Header- und Datenblockinformationen der einzelnen
Datenpakete und teilt diese in Objektvariablen ein,
die später von außen aufgerufen werden können.

# Funktionsweise: Zuerst muss ein Socket erstellt werden.
Demnach kann man sich ein Datenpaket vom Socket holen.
Die Datenpakete müssen nach folgender Struktur aufgerufen werden:

- Ethernet Frame
    - Internet Protocol v4 (IPv4)
        - Transmission Control Protocl (TCP)
        - User Datagram Protocol (UDP)
        - Internet Control Message Protocol (ICMP)

Vom Datenpaket wird ein ethernetFrame-Objekt erstellt und die
gewünschten Informationen (bereits von diesem Modul
geparst und in Objektvariablen eingeteilt) angezeigt. Analog
geschieht es mit allen anderen Protokollen. Der Datablock
des jeweiligen Netzwerklayers ist dann der Header + Data
Block des nächsten Netzwerklayers.

# Testbeispiel zum importieren und aufrufen des Moduls:

from networkSniffer import *
mainSocket = sniffer.init()
rawData, socketAdr = sniffer.getPacket(mainSocket)
eth = ethernetFrame(rawData)
print(eth.data)
if eth.type == 8:
    ipv4 = ipv4Packet(eth.data)
    print(ipv4.sourceIp)
    if ipv4.protocol == 6:
        tcp = tcpSegment(ipv4.data)
        print(tcp.data)
    if ipv4.protocol == 17:
        udp = udpSegment(ipv4.data)
        print(udp.data)
    if ipv4.protocol == 1:
        icmp = icmpSegment(ipv4.data)
        print(icmp.data)

# Benutzte externe Module, Code Snippets:

Packetsniffing-Videotutorialreihe: https://www.youtube.com/watch?v=WGJC5vT5YJo
Credits: thenewboston
Lizenz: Standard YouTube Licence

Hexdump: https://pypi.python.org/pypi/hexdump
Credits: anatoly techtonik <techtonik@gmail.com>, George Schizas, Ian Land
Lizenz: Public Domain

"""

import socket  # importieren natives socket-Modul
import struct  # importieren natives struct-Modul
from hexdump import hexdump  # importieren aus dem externem hexdump-Modul nur die hexdump-Funktion


class sniffer:
    # Basisklasse

    def init():
        # Erstellen Socket.
        # Return: socket ID (sollte einer Variable zugewiesen werden)

        # AF_PACKET - retrieven Datenpaket
        # SOCK_RAW - retrieven raw data
        # ntohs(3) - konvertieren 16-bit positive int zum network byte-order (big-endian)
        return socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))


    def getPacket(socketRef):
        # Holen Datenpaket.
        # Parameter: socketRef (Referenz zum Socket, welche der init() Funktion zugewiesen wurde)
        # Return (Tupel): <raw data>,<additional socket informations>

        # Laut: https://en.wikipedia.org/wiki/Maximum_transmission_unit#MTUs_for_common_media
        # gilt, dass das größtmögliche IPv4-Datenpaket nicht größer als 64KB betragen kann
        # Reservieren etwas darüber: 65535 bytes: (2^16)-1
        return socketRef.recvfrom(65535)


class ethernetFrame:
    # Ethernet Frame nach Typ II (Ethernet II), Parsen nach:
    # https://en.wikipedia.org/wiki/Ethernet_frame#Ethernet_II

    def __init__(self, rawData):
        # Initialisieren das Objekt des Ethernet Frames
        # Parameter: rawData (reine Bytesequenz des Datenpakets aus dem Socket)

        # Methode __init__ ist Konstruktor des Objekts,
        # wird automatisch ausgeführt beim Erstellen des Objekts

        # Entpacken ethernetFrame-struct:
        # Structs sind verpackte Byte-Reihenfolgen
        # Durch bestimmte string-format Konventionen sind diese
        # leicht in Variablen zu entpacken. Es gilt:
        # ! - benutzen network byte-order (big-endian)
        # Xs = X ist anzahl in bytes, s ist string
        # B = 1-byte integer
        # H = 2-byte integer
        # L = 4-byte integer
        # rawData[:14] = struct, aus dem entpackt werden soll (aus Bytesequenz von 0 bis 14 Bytes)
        # mehr dazu: https://docs.python.org/3/library/struct.html
        _destMac, _sourceMac, _type = struct.unpack('! 6s 6s H', rawData[:14])
        # Setzen eigene global Objektvariablen zu denen, welche entpackt wurden
        self.destMac = self.byteSeqToMac(_destMac)  # formatieren zur lesbaren MAC-Adresse
        self.sourceMac = self.byteSeqToMac(_sourceMac)  # formatieren zur lesbaren MAC-Adresse
        self.type = socket.htons(_type)  # konvertieren 16-bit int zum network byte-order
        self.totalLength = len(rawData)
        self.dataLength = len(rawData[14:])  # Länge von rawData von Byte 14 bis zum Ende
        # Nachdem der Header geparst wurde, returnen wir den restlichen Datablock
        self.data = rawData[14:]  # rawData von Byte 14 bis zum Ende

    def byteSeqToMac(self, byteSeq):
        # Formatiert Bytesequenz zur gut lesbaren MAC-Adresse
        # Parameter: byteSeq (Bytesequenz)
        # Return: formatierter String (MAC-Adresse)

        # Map iteriert durch Bytesequenz, formatiert jedes Element nach
        # {:02x} (Hex mit 2 Slots, die bei Bedarf mit Nullen gefüllt werden)
        # und fügt diese einem Bytearray hinzu
        byteArray = map('{:02x}'.format, byteSeq)
        # Join iteriert durch das Bytearray, fügt zwischen jedes Element ein
        # string ':' ein, konvertiert jedes Element zu upper-case, returned string
        macStr = ':'.join(byteArray).upper()
        return macStr


# Initiieren einige global Variablen durch welche später Werte zur
# Verifikation von TCP, UDP, ICMP verabreicht werden:
global rawSourceIp
global rawDestIp
global rawProtocol


class ipv4Packet:
    # IPv4-Paket, Parsen nach:
    # https://en.wikipedia.org/wiki/IPv4#Header

    def __init__(self, rawData):
        # Initialisieren das Objekt des IPv4-Pakets
        # Parameter: rawData (reine Bytesequenz des übrigen Datablocks des Ethernet Frames)

        # Ermitteln Headerlänge
        versionHeaderLength = rawData[0]  # nehmen ersten Byte
        self.version = versionHeaderLength >> 4  # rechter Bitshift um 4 um Version zu parsen
        # Headerlänge mit 0xf verUNDet (halber Byte, 4 bit rechts) um die Version links zu eliminieren
        # Nach einer Konvention muss man das Resultat *4 um die korrekte Headerlänge zu erlangen
        self.headerLength = (versionHeaderLength & 15) * 4
        # Entpacken ipv4-struct:
        _serviceType, _totalLength, _id, _flagsFragmentOffset, _timeToLive, _protocol, _headerChecksum, _sourceIp, _destIp = struct.unpack(
            '! 1x B H H H B B H 4s 4s', rawData[:20])
        self.serviceType = hex(_serviceType)  # hex(x) konvertiert int zu hex
        self.totalLength = _totalLength
        self.id = _id
        self.idHex = hex(_id)
        # Für den df- (Bit 14 von rechts) und mf-Flag (Bit 13 von rechts) im 7+8. Byte bilden wir:
        # df-Flag: VerUNDung mit 2^14 (zum Eliminieren der restlichen Bits) und Bitshift nach ganz rechts, da big-endian
        # mf-Flag: VerUNDung mit 2^13 (zum Eliminieren der restlichen Bits) und Bitshift nach ganz rechts, da big-endian
        self.dfFlag = (_flagsFragmentOffset & 16384) >> 14
        self.mfFlag = (_flagsFragmentOffset & 8192) >> 13
        # Für den Fragment Offset (Byte 7+8) bilden wir:
        # VerUNDung von (2^13)-1 für 13 totale (0-12) Slots von rechts (eliminieren somit die Flags)
        self.fragOffset = _flagsFragmentOffset & 8191
        self.timeToLive = _timeToLive
        self.protocol = int(_protocol)
        self.headerChecksum = hex(_headerChecksum)
        # Initiieren verifiedChecksum, welche später bei der Verifikation geändert wird
        self.verifiedChecksum = 0xffff
        self.sourceIp = self.byteSeqToIp(_sourceIp)
        self.destIp = self.byteSeqToIp(_destIp)
        # Importieren globale Variablen und ordnen diesen raw Source Ip, Dest Ip, Protocol zu zur späteren Verifikation der Checksummen
        global rawSourceIp
        rawSourceIp = _sourceIp
        global rawDestIp
        rawDestIp = _destIp
        global rawProtocol
        rawProtocol = _protocol
        self.headerData = rawData[:self.headerLength]
        # Nachdem der Header geparst wurde, returnen wir den restlichen Datablock
        self.data = rawData[self.headerLength:]

    def byteSeqToIp(self, byteSeq):
        # Formatiert Bytesequenz zur gut lesbaren IP-Adresse
        # Parameter: byteSeq (Bytesequenz)
        # Return: formatierter String (IP-Adresse)

        # Map iteriert durch Bytesequenz, konvertiert jedes Element zu
        # einem string und fügt diese einem Stringarray hinzu
        strArray = map(str, byteSeq)
        # Join iteriert durch das Stringarray, fügt zwischen jedes Element ein
        # string '.' ein, returned string
        ipStr = '.'.join(strArray)
        return ipStr

    def verifyChecksum(self):
        # Verifiziert Checksumme eines IPv4-Pakets
        # Verifizieren nach: https://en.wikipedia.org/wiki/IPv4_header_checksum#Example:_verifying_an_IPv4_header_checksum
        # Return: string (correct oder incorrect)

        data = self.headerData
        dataLength = len(data)  # Länge des Datablocks in Bytes
        checksum = 0x0
        evenDataLength = (dataLength // 2) * 2  # Bestimmen die nächstkleinere gerade Zahl von dataLength
        # Iterieren durch den Datablock, summieren 16-Bit Wörter miteinander
        for i in range(0, evenDataLength, 2):
            # 16-Bit Wörter werden gebildet aus zwei konkatenierten Strings (Byte + Byte)
            checksum += int((str("%02x" % (data[i],)) + str("%02x" % (data[i + 1],))),
                            16)  # "%02x" konvertiert Byte in zweistelligen Hex
        # Bei ungerader Anzahl an Bytes im Datablock, addieren den letzten Byte zur Checksumme
        if dataLength % 2 == 1:
            checksum += int(str("%02x" % (data[evenDataLength],)))
        # Behalten nur die letzten 16 Bits der 32-Bit langen Checksumme und summieren die Übertrage
        while checksum >> 16:
            checksum = (checksum >> 16) + (checksum & 0xffff)
        # Bilden das Komplement der Checksumme
        # Falls die ersten 2 Bytes 0x0 sind, gilt die Checksumme als korrekt
        checksum = (~checksum) & 0xffff
        # Kopieren die finale Checksumme in die Objektvariable verifiedChecksum (aus dem __init__)
        self.verifiedChecksum = hex(checksum)
        # Return:
        if checksum == 0x0:
            return 'correct'
        else:
            return 'incorrect'


class tcpSegment:
    # TCP-Segment, Parsen nach:
    # https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure

    def __init__(self, rawData):
        # Initialisieren das Objekt des TCP-Segments
        # Parameter: rawData (reine Bytesequenz des übrigen Datablocks des IPv4-Pakets)

        # Entpacken tcp-struct:
        _sourcePort, _destPort, _seqNum, _ackNum, _offsetReservedFlags, _window, _checksum, _urgPointer = struct.unpack(
            '! H H L L H H H H', rawData[:20])
        self.sourcePort = _sourcePort
        self.destPort = _destPort
        self.seqNum = _seqNum
        self.ackNum = _ackNum
        # Offset um 12 bits nach rechts verschoben, da big-endian (eliminiert die Flag-Bits)
        # Nach einer Konvention muss man das Resultat *4 um den korrekten Offset zu erlangen
        offset = (_offsetReservedFlags >> 12) * 4
        # Für die TCP Flags im 13+14. Byte bilden wir:
        # cwr-Flag (Bit 7 von rechts): VerUNDung mit 2^7 (zum Eliminieren der restlichen Bits) und Bitshift nach ganz rechts, da big-endian
        # ece-Flag (Bit 6 von rechts): VerUNDung mit 2^6 (zum Eliminieren der restlichen Bits) und Bitshift nach ganz rechts, da big-endian
        # ...analog für die restlichen Flags...
        self.cwrFlag = (_offsetReservedFlags & 128) >> 7
        self.eceFlag = (_offsetReservedFlags & 64) >> 6
        self.urgFlag = (_offsetReservedFlags & 32) >> 5
        self.ackFlag = (_offsetReservedFlags & 16) >> 4
        self.pshFlag = (_offsetReservedFlags & 8) >> 3
        self.rstFlag = (_offsetReservedFlags & 4) >> 2
        self.synFlag = (_offsetReservedFlags & 2) >> 1
        self.finFlag = (_offsetReservedFlags & 1)
        self.window = _window
        self.checksum = hex(_checksum)
        # Initiieren verifiedChecksum, welche später bei der Verifikation geändert wird
        self.verifiedChecksum = 0xffff
        self.urgPointer = hex(_urgPointer)
        self.headerLength = len(rawData[:offset])
        self.headerData = rawData[:self.headerLength]
        self.totalLength = len(rawData)
        self.totalData = rawData
        self.dataLength = len(rawData[offset:])
        # Nachdem der Header geparst wurde, returnen wir den restlichen Datablock
        self.data = rawData[offset:]

    def verifyChecksum(self):
        # Verifiziert Checksumme eines TCP-Segments
        # Verifizieren nach: https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_checksum_for_IPv4
        # Return: string (correct oder incorrect)

        # Importieren globale Variablen des IPv4-Pakets (notwendig für den Pseudoheader)
        global rawSourceIp
        global rawDestIp
        global rawProtocol
        # Bilden Pseudoheader:
        pseudoHeader = rawSourceIp + rawDestIp + rawProtocol.to_bytes(2, 'big') + self.totalLength.to_bytes(2, 'big')
        # Nach einer Konvention besteht der Datablock aus Pseudoheader + TCP Header + TCP Data:
        data = pseudoHeader + self.totalData
        dataLength = len(data)  # Länge des Datablocks in Bytes
        # Wenn die Länge des Datablocks ungerade ist, müssen wir ein 00 Byte hinten anfügen
        # So geht man sicher, dass keine IndexOutOfBounds-Errors bei späterer Summierung von mehrfachen (Byte+Byte) auftreten
        if dataLength % 2 == 1:
            data += bytes(1)
        checksum = 0x0
        # Iterieren durch die (neue) Gesamtlänge des Datablocks
        for i in range(0, len(data), 2):
            # Addieren bei der IPv4-Packet-Validierung die (Byte+Byte) nacheinander auf:
            checksum += int((str("%02x" % (data[i],)) + str("%02x" % (data[i + 1],))), 16)
        # Behalten nur die letzten 16 Bits der 32-Bit langen Checksumme und summieren die Übertrage
        while checksum >> 16:
            checksum = (checksum >> 16) + (checksum & 0xffff)
        # Bilden das Komplement der Checksumme
        # Falls die ersten 2 Bytes 0x0 sind, gilt die Checksumme als korrekt
        checksum = (~checksum) & 0xffff
        self.verifiedChecksum = hex(checksum)
        if checksum == 0x0:
            return 'correct'
        else:
            return 'incorrect'


class udpSegment:
    # UDP-Segment, Parsen nach:
    # https://en.wikipedia.org/wiki/User_Datagram_Protocol#Packet_structure

    def __init__(self, rawData):
        # Initialisieren das Objekt des UDP-Segments
        # Parameter: rawData (reine Bytesequenz des übrigen Datablocks des IPv4-Pakets)

        # Entpacken udp-struct:
        _sourcePort, _destPort, _length, _checksum = struct.unpack('! H H H H', rawData[:8])
        self.sourcePort = _sourcePort
        self.destPort = _destPort
        self.length = _length
        self.checksum = hex(_checksum)
        # Initiieren verifiedChecksum, welche später bei der Verifikation geändert wird
        self.verifiedChecksum = 0xffff
        self.totalData = rawData
        # Nachdem der Header geparst wurde, returnen wir den restlichen Datablock
        self.data = rawData[8:]

    def verifyChecksum(self):
        # Verifiziert Checksumme eines UDP-Segments (analog der Verifikation der Checksummen des TCP-Segments)
        # Verifizieren nach: https://en.wikipedia.org/wiki/User_Datagram_Protocol#Checksum_computation
        # Return: string (correct oder incorrect)

        # Importieren globale Variablen des IPv4-Pakets (notwendig für den Pseudoheader)
        global rawSourceIp
        global rawDestIp
        global rawProtocol
        # Bilden Pseudoheader:
        pseudoHeader = rawSourceIp + rawDestIp + rawProtocol.to_bytes(2, 'big') + self.length.to_bytes(2, 'big')
        # Nach einer Konvention besteht der Datablock aus Pseudoheader + UDP Header + UDP Data:
        data = pseudoHeader + self.totalData
        dataLength = len(data)
        # Wenn die Länge des Datablocks ungerade ist, müssen wir ein 00 Byte hinten anfügen
        # So geht man sicher, dass keine IndexOutOfBounds-Errors bei späterer Summierung von mehrfachen (Byte+Byte) auftreten
        if dataLength % 2 == 1:
            data += bytes(1)
        checksum = 0x0
        # Iterieren durch die (neue) Gesamtlänge des Datablocks
        for i in range(0, len(data), 2):
            # Addieren bei der IPv4-Packet-Validierung die (Byte+Byte) nacheinander auf:
            checksum += int((str("%02x" % (data[i],)) + str("%02x" % (data[i + 1],))), 16)
        # Behalten nur die letzten 16 Bits der 32-Bit langen Checksumme und summieren die Übertrage
        while checksum >> 16:
            checksum = (checksum >> 16) + (checksum & 0xffff)
        # Bilden das Komplement der Checksumme
        # Falls die ersten 2 Bytes 0x0 sind, gilt die Checksumme als korrekt
        checksum = (~checksum) & 0xffff
        self.verifiedChecksum = hex(checksum)
        if checksum == 0x0:
            return 'correct'
        else:
            return 'incorrect'


class icmpSegment:
    # ICMP-Segment, Parsen nach:
    # https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#ICMP_datagram_structure

    def __init__(self, rawData):
        # Initialisieren das Objekt des ICMP-Segments
        # Parameter: rawData (reine Bytesequenz des übrigen Datablocks des IPv4-Pakets)

        # Entpacken icmp-struct:
        _messageType, _code, _checksum = struct.unpack('! B B H', rawData[:4])
        self.messageType = _messageType
        self.code = _code
        self.checksum = hex(_checksum)
        # Initiieren verifiedChecksum, welche später bei der Verifikation geändert wird
        self.verifiedChecksum = 0xffff
        self.totalData = rawData
        self.totalLength = len(self.totalData)
        # Nachdem der Header geparst wurde, returnen wir den restlichen Datablock
        self.data = rawData[4:]

    def verifyChecksum(self):
        # Verifiziert Checksumme eines ICMP-Segments
        # Verifizieren nach: https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#header_checksum
        # Return: string (correct oder incorrect)

        data = self.totalData
        dataLength = len(data)
        # Wenn die Länge des Datablocks ungerade ist, müssen wir ein 00 Byte hinten anfügen
        # So geht man sicher, dass keine IndexOutOfBounds-Errors bei späterer Summierung von mehrfachen (Byte+Byte) auftreten
        if dataLength % 2 == 1:
            data += bytes(1)
        checksum = 0x0
        # Iterieren durch die (neue) Gesamtlänge des Datablocks
        for i in range(0, len(data), 2):
            # Addieren bei der IPv4-Packet-Validierung die (Byte+Byte) nacheinander auf:
            checksum += int((str("%02x" % (data[i],)) + str("%02x" % (data[i + 1],))), 16)
        # Behalten nur die letzten 16 Bits der 32-Bit langen Checksumme und summieren die Übertrage
        while checksum >> 16:
            checksum = (checksum >> 16) + (checksum & 0xffff)
        # Bilden das Komplement der Checksumme
        # Falls die ersten 2 Bytes 0x0 sind, gilt die Checksumme als korrekt
        checksum = (~checksum) & 0xffff
        self.verifiedChecksum = hex(checksum)
        if checksum == 0x0:
            return 'correct'
        else:
            return 'incorrect'


def convertToHexdump(rawData,result='return'):
    # Konvertieren raw data in einen Hexdump (Hex + Entschlüsselter Text nach UTF-8 / ASCII)
    # Parameter: rawData (reine Bytesequenz)
    # Return: string

    # rufen die hexdump-Funktion des externen Hexdump-Moduls auf
    return hexdump(rawData,result)


def convertToRaw(rawData):
    # Konvertieren raw data in lesbaren Text (Entschlüsselter Text nach UTF-8 / ASCII)
    # Parameter: rawData (reine Bytesequenz)
    # Return: string

    _temp = rawData
    try:  # Probieren nach utf-8 zu entschlüsseln
        _temp = _temp.decode('utf-8')
    except:
        try:  # probieren nach ascii zu entschlüsseln
            _temp = _temp.decode('ascii')
        except:  # ansonsten returnen den Ursprungstext (raw data)
            pass
    return _temp


def convertToHex(rawData):
    # Formatiert Bytesequenz zur gut lesbaren IP-Adresse
    # Parameter: rawData (reine Bytesequenz)
    # Return: string

    # Map iteriert durch Bytesequenz, formatiert jedes Element nach
    # {:02x} (Hex mit 2 Slots, die bei Bedarf mit Nullen gefüllt werden)
    # und fügt diese einem Bytearray hinzu
    byteArray = map('{:02x}'.format, rawData)
    # Join iteriert durch das Bytearray, fügt zwischen jedes Element ein
    # string '.' ein, konvertiert jedes Element zu upper-case, returned string
    hexStr = ' '.join(byteArray).upper()
    return hexStr

# ENDE
