"""
Das Prinzip des Programmes ist die Bearbeitung der Linux-integrierten iptables
über die in der iptc vorhanden Funktionen

Die iptables bestehen aus verschiedenen
    Tabellen: Filter, Nat, Mangle, Raw
    Chains innerhalb der einzelnen Tables: INPUT, OUTPUT, FORWARD, PREROUTING, POSTROUTING
    Rules die in den Chains liegen und selbst definiert werden können

Weitere Informationen zu iptables finden sich unter: https://wiki.ubuntuusers.de/iptables2/

Mit den Rules können Regeln aufgestellt werden, die festlegen wie mit Datenpaketen umgegangen werden soll
Die geschriebenen Funktionen dieses Programmes erstellen beim Aufruf solche Regeln, mit denen IP-Adressen und
Bereiche von IP-Adressen blockiert und freigegeben werden können.
"""

# Import der iptc Library zum Nutzen der Funktionen dieser
import os


# Klasse zum Handling mit Ipv4 Adresse
class ipv4():

    # Blockiert die übergebene IP in der FILTER Tabelle
    # Die FORWARD Chain muss gewählt sein, um die Regeln für alle mit dem AP verbundenen Geräte festzulegen
    # Die IP-Adresse wird als string übergeben
    def blockIp(str):
        os.system("sudo iptables -A FORWARD -s " + str + " -j DROP")

    # Blockiert den übergebenen Bereich von IP-Adressen in der FILTER Tabelle
    def blockIpRange(str):
        os.system("sudo iptables -A FORWARD -m iprange --src-range " + str + " -j DROP")

    # Gibt die übergebene IP-Adresse in der FILTER Tabelle wieder frei
    def unblockIp(str):
        os.system("sudo iptables -D FORWARD -s " + str + " -j DROP")

    # Gibt den übergebenen Bereich von IP-Adresse in der FILTER Tabelle wieder frei
    def unblockIpRange(str):
        os.system("sudo iptables -D FORWARD -m iprange --src-range " + str + " -j DROP")
