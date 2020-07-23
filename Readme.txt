RaspInTheMiddle2 ist eine Erweiterung der Studienprojekt-Software RaspInTheMiddle. Diese Version bietet eine Web-Oberfläche der vorherigen Version mit kleinen Änderungen.


#Material
############################################################################
Zur Ausführung der Web-Anwendung müssen folgende Python-Bibliotheken installiert werden (zusaätzlich zu den vorher verwendten Bibliotheken):
- Json Pickle : https://jsonpickle.github.io/
- Flask : https://pypi.org/project/Flask/
- Bluepy : https://github.com/IanHarvey/bluepy
- Crythography : https://pypi.org/project/cryptography/
- Flask Socket IO : http://flask-socketio.readthedocs.io/en/latest/
####################################################################################


#Wichtig
#######################################################################################
Die folgenden Dateien müssen mit --- --- rwx  Permissions immer im Projekt zu finden sein .

- key.txt
- manufacturers.list
- database.txt
- blockedIpRanges.txt
- blockedIpAdresses.txt
- GeoIP2-ISP.mmdb
- GeoLite2-City.mmdb

Sollte eine der o.g Dateien fehlen, dann könnte es zu einem Lauffehler geführt werden
#################################################################################

#Funktionsweise
#################################################################################

- Aufruf der Hauptseite bedeutet, dass Sie sich als Gast erkennen gelassen haben : Nur Scanverlaufanzeige möglich  Scanabbruch und -start
- Aufruf der login Seite : Ermöglicht ein Einloggen
- Aufruf der register Seite : Ermöglicht eine Registrierung eines Users (nur bei Admin möglich)
- Aufruf der Scan Seite bei Eingeloggten :
  * Sortierung der Scan-Ergebnisse möglich (nur wenn der Scan nicht in Gang läuft) : normaler User und Admin
  * Speichern der Scan- und Sortierungsergebenisse möglich : Admin
  * Neustart des Scan-Vorgangs : normaler User und Admin
  * Beenden des Scan-Vorgangs : normaler User und Admin


###############################################################################################


#Lücken
#########################################################################
Momentan ist leider nur ein fester Admin mit einem festen Passwort gespeichert. Eine Änderung sowohl des Admin-Namens als auch des Admin-Passworts ist nicht möglich.
######################################################################


Urheber
Brandon Njimefo
Landry Atamegui
Phill Kaulich