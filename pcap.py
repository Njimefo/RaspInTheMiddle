# -*- coding: utf-8 -*-

"""
pcap.py - Laden und Speichern von PCAP-Dateien, in Wireshark verwendbar

-> Hinweise:
Pakete werden mit einem Delay geschrieben. Bei zufälligem Abbruch
könnten so einige Pakete nicht mehr zu Ende geschrieben werden.
Beim Laden würden dann nicht alle Pakete vollständig und korrekt geladen werden.

-> Lizenz für das benutzte "pcapfile" Modul:
https://pypi.python.org/pypi/pypcapfile
Autor: Kyle Isom
ISC License

-> Autor: Jean Chouameni
"""


import struct
import time

#laden pcap-ladefunktion aus dem 'pcapfile'-modul
from pcapfile import savefile


class pcapSave:

    #NTB
    #Modifiziert
    def __init__(self, path,mode='wb'):

        self.pcap = open(path, mode) #schreiben 'wb' = binärdatei

        """
        Benutzen Wireshark's Libpcap File Format nach den Konventionen aus:
        https://wiki.wireshark.org/Development/LibpcapFileFormat

        Folgendes kommt in den Header der Datei (Global Header):

        magic_number: used to detect the file format itself and the byte ordering. The writing application writes 0xa1b2c3d4 with it's native byte ordering format into this field. The reading application will read either 0xa1b2c3d4 (identical) or 0xd4c3b2a1 (swapped). If the reading application reads the swapped 0xd4c3b2a1 value, it knows that all the following fields will have to be swapped too. For nanosecond-resolution files, the writing application writes 0xa1b23c4d, with the two nibbles of the two lower-order bytes swapped, and the reading application will read either 0xa1b23c4d (identical) or 0x4d3cb2a1 (swapped).
        version_major, version_minor: the version number of this file format (current version is 2.4)
        thiszone: the correction time in seconds between GMT (UTC) and the local timezone of the following packet header timestamps. Examples: If the timestamps are in GMT (UTC), thiszone is simply 0. If the timestamps are in Central European time (Amsterdam, Berlin, ...) which is GMT + 1:00, thiszone must be -3600. In practice, time stamps are always in GMT, so thiszone is always 0.
        sigfigs: in theory, the accuracy of time stamps in the capture; in practice, all tools set it to 0
        snaplen: the "snapshot length" for the capture (typically 65535 or even more, but might be limited by the user), see: incl_len vs. orig_len below
        network: link-layer header type, specifying the type of headers at the beginning of the packet (e.g. 1 for Ethernet, see tcpdump.org's link-layer header types page for details); this can be various types such as 802.11, 802.11 with various radio information, PPP, Token Ring, FDDI, etc.
        """

        # Benutzen structs, wo gilt:
        #@ = using native byte order
        # i = int = 4 byte
        # I = unsigned int = 4 byte
        # H = unsigned short  = 2 byte

        #schreiben in header der datei:
        self.pcap.write(struct.pack('@ I H H i I I I', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

    def writePacket(self, data,timeDataGiven = False):

        if not timeDataGiven:
            """
                    Benutzen Wireshark's Libpcap File Format nach den Konventionen aus:
                    https://wiki.wireshark.org/Development/LibpcapFileFormat

                    Folgendes kommt vor jedem Datenpaket (Packet Header):

                    ts_sec: the date and time when this packet was captured. This value is in seconds since January 1, 1970 00:00:00 GMT; this is also known as a UN*X time_t. You can use the ANSI C time() function from time.h to get this value, but you might use a more optimized way to get this timestamp value. If this timestamp isn't based on GMT (UTC), use thiszone from the global header for adjustments.
                    ts_usec: in regular pcap files, the microseconds when this packet was captured, as an offset to ts_sec. In nanosecond-resolution files, this is, instead, the nanoseconds when the packet was captured, as an offset to ts_sec /!\ Beware: this value shouldn't reach 1 second (in regular pcap files 1 000 000; in nanosecond-resolution files, 1 000 000 000); in this case ts_sec must be increased instead!
                    incl_len: the number of bytes of packet data actually captured and saved in the file. This value should never become larger than orig_len or the snaplen value of the global header.
                    orig_len: the length of the packet as it appeared on the network when it was captured. If incl_len and orig_len differ, the actually saved packet size was limited by snaplen.
                    """

            # kalkulieren timestamp:
            timestampSec, timestampMicroSec = map(int, str(time.time()).split(
                '.'))  # nehmen unix-time und spalten diese nach sekunden und mikrosekunden

            # formatieren mikrosekunden nach konventionen, max. 6 stellen
            timestampMicroSecStr = str(timestampMicroSec)[:6]  # schneiden die ersten 6 ziffern ab
            timestampMicroSecStr = timestampMicroSecStr.ljust(6,
                                                              '0')  # füllen hinten mit nullen (falls zahl kleiner als 6 stellen)
            timestampMicroSec = int(timestampMicroSecStr)  # konvertieren nach integer

            # schreiben vor jedem datenpaket:
            self.pcap.write(struct.pack('@ I I I I', timestampSec, timestampMicroSec, len(data), len(data)))

            # und fügen den datablock (raw-datenpaket) hinzu:
            self.pcap.write(data)
        else:
            # schreiben vor jedem datenpaket:
            self.pcap.write(struct.pack('@ I I I I', data.TimestampSec, data.TimestampMicroSec, len(data.Data), len(data.Data)))

            # und fügen den datablock (raw-datenpaket) hinzu:
            self.pcap.write(data.Data)

    def close(self):

        #schliessen pcap-speicherung
        self.pcap.close()



class pcapLoad:

    def __init__(self, path):
        pcapObj_ = open(path, 'rb') #lesen 'rb' - Binärdatei
        self.pcapObj = savefile.load_savefile(pcapObj_, verbose=True)

    def getPacketCount(self):
        return len(self.pcapObj.packets)

    def loadPacketData(self, index):
        return self.pcapObj.packets[index].raw()

    def loadPacketTimestampSec(self, index):
        return self.pcapObj.packets[index].timestamp

    def loadPacketTimestampMicroSec(self, index):
        return self.pcapObj.packets[index].timestamp_us