//gibt an ob der User ein Gast ist
var isGast = true;

//Gibt an ob die Daten empfangen werden
var isCapturing = false;

//Liste bekannter Firmen  für Filter-Zwecke
var firms = ["Google", "Facebook", "Yahoo", "Facebook", "Youtube", "Amazon", "CloudFlare", "Twiter", "Akamai", "Wikimedia", "Wikipedia"];

//empfangeene Pakete
var receivedPackets = [];

//anzuzeigende Daten
var toDisplayData = [];

//angezeigte Daten
var displayedData = [];

//herausgefilterte Daten
var filteredPackets = [];

//zuletzt selektierte Zeilenummer
var lastSelectedRow = -1;

//Container für die Tabelle
var tableWrapper;

//zuletzt gespeicherte Hintergrundfarbe von einer Zeile
var lastBackColor;

//Socket Variable
var socket;

//Gibt an ob die Daten gefiltert sind
var filtered = false;

//Erzeugt ein neues HTML-Element mit Hilfe seines Namens und seiner Attribute
var createElement = (function () {

    if (/*@cc_on @*//*@if (@_win32)!/*@end @*/false) {
        on;
        var attrTranslations =
            {
                "class": "className",
                "for": "htmlFor"
            };

        var setAttribute = function (element, attr, value) {
            if (attrTranslations.hasOwnProperty(attr)) {
                element[attrTranslations[attr]] = value;
            }
            else if (attr == "style") {
                element.style.cssText = value;
            }
            else {
                element.setAttribute(attr, value);
            }
        };

        return function (tagName, attributes) {
            attributes = attributes || {};

            // See http://channel9.msdn.com/Wiki/InternetExplorerProgrammingBugs
            if (attributes.hasOwnProperty("name") ||
                attributes.hasOwnProperty("checked") ||
                attributes.hasOwnProperty("multiple")) {
                var tagParts = ["<" + tagName];
                if (attributes.hasOwnProperty("name")) {
                    tagParts[tagParts.length] =
                        ' name="' + attributes.name + '"';
                    delete attributes.name;
                }
                if (attributes.hasOwnProperty("checked") &&
                    "" + attributes.checked == "true") {
                    tagParts[tagParts.length] = " checked";
                    delete attributes.checked;
                }
                if (attributes.hasOwnProperty("multiple") &&
                    "" + attributes.multiple == "true") {
                    tagParts[tagParts.length] = " multiple";
                    delete attributes.multiple;
                }
                tagParts[tagParts.length] = ">";

                var element =
                    document.createElement(tagParts.join(""));
            }
            else {
                var element = document.createElement(tagName);
            }

            for (var attr in attributes) {
                if (attributes.hasOwnProperty(attr)) {
                    setAttribute(element, attr, attributes[attr]);
                }
            }

            return element;
        };
    }

    else {
        return function (tagName, attributes) {
            attributes = attributes || {};
            var element = document.createElement(tagName);
            for (var attr in attributes) {
                if (attributes.hasOwnProperty(attr)) {
                    element.setAttribute(attr, attributes[attr]);
                }
            }
            return element;
        };
    }
})();

//Entfernt alle Zeilen von der Tabelle
function deleteAllRows() {
    var packetInfos = document.getElementById('packetInfos');

    while (packetInfos.rows.length > 1) {
        packetInfos.deleteRow(packetInfos.rows.length - 1);
    }
}

//stellt die Verbindung mit dem Server her und fängt an, die Pakete zu empfangen
function ConnectToSocketAndStartReceive() {
    deleteAllRows();
    receivedPackets = [];
    toDisplayData = [];
    displayedData = [];
    filteredPackets = [];
    var filters = document.getElementById('filters');
    var saveBtn = document.getElementById('saveBtn');
    if (!isGast) {
        saveBtn.disabled = true;

    }
    filters.disabled = true;
    socket = io.connect('http://' + document.domain + ':' + location.port + '/packetTransfer');
    tableWrapper = document.getElementById('tableWrapper');

    isCapturing = true;
    socket.on('newpacket', function (msg) {

        if (!isCapturing) return;
        var packet = JSON.parse(msg.packet);
        receivedPackets.push(packet);
        if (receivedPackets.length >= 20)
            toDisplayData.push(packet);
        else {
            displayedData.push(packet);
            AddPacketRow(packet);
        }


    });

}

//Nach Initialisierung stellt die Verbindung mit dem Server her und fängt an, die Pakete zu empfangen
$(document).ready(function () {

    var saveBtn = document.getElementById('saveBtn');
    isGast = saveBtn == undefined;
    ConnectToSocketAndStartReceive();
});

//Fügt neue Zeilen in der Tabelle
function AddNewRows(nbreOfRows) {
    if (isCapturing)
        AddPacketRows(nbreOfRows);
}

//Fügt neue Zeilen in der Tabelle mit den Paket-Daten
function AddPacketRows(nbreOfElement) {

    while (nbreOfElement != 0 && toDisplayData.length != 0) {
        AddPacketRow(toDisplayData[0]);
        displayedData.push(toDisplayData[0]);
        toDisplayData.shift();

    }
}

//Startet das Empfangen von Paketen
function StartCapture() {
    if (isCapturing) return;
    ConnectToSocketAndStartReceive();

}

//Endet das Empfangen von Paketen
function StopCapture() {
    if (!isCapturing) return;
    isCapturing = false;

    if (socket != null) socket.disconnect();

    var table = document.getElementById("packetInfos");


    var rows = table.getElementsByTagName("tr");
    for (i = 0; i < rows.length; i++) {
        var currentRow = table.rows[i];
        var createClickHandler =
            function (row, index) {
                return function () {
                    if (lastSelectedRow != -1)
                        rows[lastSelectedRow].style = lastBackColor;
                    lastBackColor = row.style.backgroundColor;
                    row.style.backgroundColor = "red";
                    lastSelectedRow = index;

                    var cell = row.getElementsByTagName("td")[0];
                    var packetId = cell.innerHTML;
                    var clickedPacket = displayedData[packetId - 1];
                    ShowData(clickedPacket);
                };
            };
        currentRow.onclick = createClickHandler(currentRow, i);
    }
    var filters = document.getElementById('filters');
    var saveBtn = document.getElementById('saveBtn');
    if (!isGast) {


        var result = JSON.parse(getData("/user/checkUser"));

        //Admin
        if (result.Result == 1) {
            saveBtn.disabled = false;
            filters.disabled = false;
        }
        //Normaler User
        else if (result.Result == 0) {
            saveBtn.disabled = true;
            filters.disabled = false;
        }
    }

    alert("Aufnahme beendet")

}

// Zeigt detaillerte Informationen über das geklickte Paket
function ShowData(data) {

    var dataTreeView = document.getElementById("dataTreeView");
    var eth_div = document.createElement("div");
    var ipv4_div = document.createElement("div");
    var geo_div = document.createElement("div");
    var isp_div = document.createElement("div");
    var segment_div = document.createElement("div");

    var eth_title = document.createElement("p");
    eth_title.innerText = "Ethernet Frame : ";
    eth_title.style.fontWeight = "900";
    eth_title.style.fontSize = "x-large";

    var eth_dataLength = document.createElement("p");
    eth_dataLength.innerText = "Größe der Daten : " + data.dataLength;
    eth_dataLength.style.fontSize = "medium";


    var eth_destMac = document.createElement("p");
    eth_destMac.innerText = "Mac-Adresse des Ziels : " + data.destMac;
    eth_destMac.style.fontSize = "medium";


    var eth_sourceMac = document.createElement("p");
    eth_sourceMac.innerText = "Mac-Adresse der Quelle : " + data.sourceMac;
    eth_sourceMac.style.fontSize = "medium";


    var eth_time = document.createElement("p");
    eth_time.innerText = "Zeit : " + data.time;
    eth_time.style.fontSize = "medium";


    var eth_totalLength = document.createElement("p");
    eth_totalLength.innerText = "Gesamtgröße : " + data.totalLength;
    eth_totalLength.style.fontSize = "medium";


    var eth_type = document.createElement("p");
    eth_type.innerText = "Typ : " + data.type;
    eth_type.style.fontSize = "medium";


    var segment_title = document.createElement("p");
    segment_title.innerText = data.Data.protocol == 6 ? 'TCP-Segement' : data.Data.protocol == 17 ? 'UDP-Segment' : data.Data.protocol == 1 ? 'ICMP-Segment' : 'Unknown-Segment';
    segment_title.style.fontWeight = "900";
    segment_title.style.fontSize = "x-large";


    var segment_checksum = document.createElement("p");
    segment_checksum.innerText = "Prüfsumme : " + data.Data.Data.checksum;
    segment_checksum.style.fontSize = "medium";

    var segment_destPort = document.createElement("p");
    segment_destPort.innerText = "Port des Ziels : " + data.Data.Data.destPort;
    segment_destPort.style.fontSize = "medium";

    var segment_sourcePort = document.createElement("p");
    segment_sourcePort.innerText = "Port der Quelle : " + data.Data.Data.sourcePort;
    segment_sourcePort.style.fontSize = "medium";

    var segment_length = document.createElement("p");
    segment_length.innerText = "Größe der Daten : " + data.Data.Data.length;
    segment_length.style.fontSize = "medium";

    var segment_verifiedChecksum = document.createElement("p");
    segment_verifiedChecksum.innerText = "Verifizierte Prüfsumme : " + data.Data.Data.verifiedChecksum;
    segment_verifiedChecksum.style.fontSize = "medium";

    var segment_verifyChecksum = document.createElement("p");
    segment_verifyChecksum.innerText = "Ergebnis der Prüfsumme : " + data.Data.Data.verifyChecksum;
    segment_verifyChecksum.style.fontSize = "medium";

    var segment_data = document.createElement("p");
    segment_data.innerText = "Daten : " + data.Data.Data.Data;
    segment_data.style.fontSize = "medium";


    var geo_title = document.createElement("p");
    geo_title.innerText = "Geo-Daten : ";
    geo_title.style.fontWeight = "9000";
    geo_title.style.fontSize = "x-large";


    var geo_cityName = document.createElement("p");
    geo_cityName.innerText = "Name der Stadt : " + data.Data.geoData.cityName;
    geo_cityName.style.fontSize = "medium";


    var geo_latitude = document.createElement("p");
    geo_latitude.innerText = "Breite : " + data.Data.geoData.latitude;
    geo_latitude.style.fontSize = "medium";


    var geo_longitude = document.createElement("p");
    geo_longitude.innerText = "Längengrad : " + data.Data.geoData.longitude;
    geo_longitude.style.fontSize = "medium";


    var geo_postalCode = document.createElement("p");
    geo_postalCode.innerText = "Postleitzahl : " + data.Data.geoData.postalCode;
    geo_postalCode.style.fontSize = "medium";


    var isp_title = document.createElement("p");
    isp_title.innerText = "ISP-Daten : ";
    isp_title.style.fontWeight = "9000";
    isp_title.style.fontSize = "x-large";


    var isp_isp = document.createElement("p");
    isp_isp.innerText = "ISP : " + data.Data.ispData.isp;
    isp_isp.style.fontSize = "medium";

    var isp_organization = document.createElement("p");
    isp_organization.innerText = "Organisation : " + data.Data.ispData.organization;
    isp_organization.style.fontSize = "medium";


    var isp_autonomus_system_number = document.createElement("p");
    isp_autonomus_system_number.innerText = "Autonome Systemnummer : " + data.Data.ispData.autonomous_system_number;
    isp_autonomus_system_number.style.fontSize = "medium";


    var isp_autonomus_system_organization = document.createElement("p");
    isp_autonomus_system_organization.innerText = "Autonome Systemorganisation: " + data.Data.ispData.autonomous_system_organization;
    isp_autonomus_system_organization.style.fontSize = "medium";


    var ipv4_title = document.createElement("p");
    ipv4_title.innerText = "IPV4 Daten : ";
    ipv4_title.style.fontWeight = "9000";
    ipv4_title.style.fontSize = "x-large";


    var ipv4_destHost = document.createElement("p");
    ipv4_destHost.innerText = "Ziel-Host : " + data.Data.destHost;
    ipv4_destHost.style.fontSize = "medium";


    var ipv4_destIp = document.createElement("p");
    ipv4_destIp.innerText = "Ip-Adresse des Ziels : " + data.Data.destIp;
    ipv4_destIp.style.fontSize = "medium";


    var ipv4_dfFlag = document.createElement("p");
    ipv4_dfFlag.innerText = "DF-Flag : " + data.Data.dfFlag;
    ipv4_dfFlag.style.fontSize = "medium";


    var ipv4_fragOffset = document.createElement("p");
    ipv4_fragOffset.innerText = "Fragment Offset : " + data.Data.fragOffset;
    ipv4_fragOffset.style.fontSize = "medium";


    var ipv4_headerChecksum = document.createElement("p");
    ipv4_headerChecksum.innerText = "Header der Prüfsumme : " + data.Data.headerChecksum;
    ipv4_headerChecksum.style.fontSize = "medium";


    var ipv4_headerLength = document.createElement("p");
    ipv4_headerLength.innerText = "Größer der Header : " + data.Data.headerLength;
    ipv4_headerLength.style.fontSize = "medium";


    var ipv4_id = document.createElement("p");
    ipv4_id.innerText = "Id : " + data.Data.id;
    ipv4_id.style.fontSize = "medium";


    var ipv4_idHex = document.createElement("p");
    ipv4_idHex.innerText = "Id in Hex : " + data.Data.idHex;
    ipv4_idHex.style.fontSize = "medium";


    var ipv4_mfFlag = document.createElement("p");
    ipv4_mfFlag.innerText = "MF-Flag : " + data.Data.mfFlag;
    ipv4_mfFlag.style.fontSize = "medium";


    var ipv4_protocol = document.createElement("p");
    ipv4_protocol.innerText = "Protokoll : " + data.Data.protocol;
    ipv4_protocol.style.fontSize = "medium";


    var ipv4_serviceType = document.createElement("p");
    ipv4_serviceType.innerText = "Typ des Services : " + data.Data.serviceType;
    ipv4_serviceType.style.fontSize = "medium";


    var ipv4_sourceIp = document.createElement("p");
    ipv4_sourceIp.innerText = "Ip-Adresse der Quelle : " + data.Data.sourceIp;
    ipv4_sourceIp.style.fontSize = "medium";


    var ipv4_srcHost = document.createElement("p");
    ipv4_srcHost.innerText = "Hostname der Quelle : " + data.Data.srcHost;
    ipv4_srcHost.style.fontSize = "medium";


    var ipv4_timeToLive = document.createElement("p");
    ipv4_timeToLive.innerText = "Zeit zu leben: " + data.Data.timeToLive;
    ipv4_timeToLive.style.fontSize = "medium";


    var ipv4_totalLength = document.createElement("p");
    ipv4_totalLength.innerText = "Gesamtgröße : " + data.Data.totalLength;
    ipv4_totalLength.style.fontSize = "medium";


    var ipv4_verifiedChecksum = document.createElement("p");
    ipv4_verifiedChecksum.innerText = "Verifizierte Prüfsumme : " + data.Data.verifiedChecksum;
    ipv4_verifiedChecksum.style.fontSize = "medium";


    var ipv4_verifyChecksum = document.createElement("p");
    ipv4_verifyChecksum.innerText = "Ergebnis der verifizierten Prüfsumme  : " + data.Data.verifyChecksum;
    ipv4_verifyChecksum.style.fontSize = "medium";


    var ipv4_version = document.createElement("p");
    ipv4_version.innerText = "Version : " + data.Data.version;
    ipv4_version.style.fontSize = "medium";


    geo_div.appendChild(geo_title);
    geo_div.appendChild(geo_cityName);
    geo_div.appendChild(geo_postalCode);
    geo_div.appendChild(geo_latitude);
    geo_div.appendChild(geo_longitude);
    geo_div.appendChild(geo_latitude);
    geo_div.style.margin = "0px 0px 0px 30px";


    isp_div.appendChild(isp_title);
    isp_div.appendChild(isp_isp);
    isp_div.appendChild(isp_organization);
    isp_div.appendChild(isp_autonomus_system_organization);
    isp_div.appendChild(isp_autonomus_system_number);
    isp_div.style.margin = "0px 0px 0px 30px";

    segment_div.appendChild(segment_title);
    segment_div.appendChild(segment_destPort);
    segment_div.appendChild(segment_sourcePort);
    segment_div.appendChild(segment_verifiedChecksum);
    segment_div.appendChild(segment_verifyChecksum);
    segment_div.appendChild(segment_length);
    segment_div.appendChild(segment_data);
    segment_div.style.margin = "0px 0px 0px 30px";

    ipv4_div.appendChild(ipv4_title);
    ipv4_div.appendChild(ipv4_destHost);
    ipv4_div.appendChild(ipv4_destIp);
    ipv4_div.appendChild(ipv4_srcHost);
    ipv4_div.appendChild(ipv4_sourceIp);
    ipv4_div.appendChild(ipv4_dfFlag);
    ipv4_div.appendChild(ipv4_fragOffset);
    ipv4_div.appendChild(ipv4_headerChecksum);
    ipv4_div.appendChild(ipv4_headerLength);
    ipv4_div.appendChild(ipv4_id);
    ipv4_div.appendChild(ipv4_idHex);
    ipv4_div.appendChild(ipv4_mfFlag);
    ipv4_div.appendChild(ipv4_serviceType);
    ipv4_div.appendChild(ipv4_timeToLive);
    ipv4_div.appendChild(ipv4_totalLength);
    ipv4_div.appendChild(ipv4_verifiedChecksum);
    ipv4_div.appendChild(ipv4_verifyChecksum);
    ipv4_div.appendChild(ipv4_version);
    ipv4_div.appendChild(segment_div);
    ipv4_div.appendChild(geo_div);
    ipv4_div.appendChild(isp_div);
    ipv4_div.style.margin = "0px 0px 0px 30px";

    eth_div.appendChild(eth_title);
    eth_div.appendChild(eth_dataLength);
    eth_div.appendChild(eth_sourceMac);
    eth_div.appendChild(eth_destMac);
    eth_div.appendChild(eth_time);
    eth_div.appendChild(eth_type);
    eth_div.appendChild(eth_dataLength);
    eth_div.appendChild(eth_totalLength);
    eth_div.appendChild(ipv4_div);


    dataTreeView.innerHTML = "";

    dataTreeView.appendChild(eth_div);

}


function PageIsUnloading() {
    if (socket != null) socket.disconnect();
}

//Liest die Filter aus und wendet die an
function GetFilters() {

    if (isCapturing) return false;

    var firmInput = document.getElementById("firmInput");
    var sourceIp = document.getElementById("sourceIp");
    var sourcePort = document.getElementById("sourcePort");
    var destIp = document.getElementById("destIp");
    var destPort = document.getElementById("destPort");
    var srcPort = parseInt(sourcePort.value);
    var dstPort = parseInt(destPort.value);
    var alles = "Firm Input : " + firmInput.value + "\nSource Ip : " + sourceIp.value + "\nSource Port : " + sourcePort.value + "\nDestination Ip : " + destIp.value + "\nDestination Port : " + destPort.value;
    var filters = document.getElementById('filters');
    filters.disabled = true;
    if (filteredPackets.length == 0) {
        if (srcPort != 'NaN' && srcPort > 1 && srcPort < 6535)
            filteredPackets = receivedPackets.filter(function (packet) {
                return packet.Data.Data.sourcePort == srcPort;
            });
    }
    else {
        if (srcPort != 'NaN' && srcPort > 1 && srcPort < 6535)
            filteredPackets = filteredPackets.filter(function (packet) {
                return packet.Data.Data.sourcePort == srcPort;
            });
    }


    if (filteredPackets.length == 0) {
        if (dstPort != 'NaN' && dstPort > 1 && dstPort < 6535)
            filteredPackets = receivedPackets.filter(function (packet) {
                return packet.Data.Data.destPort == dstPort;
            });
    }
    else {
        if (srcPort != 'NaN' && srcPort > 1 && srcPort < 6535)
            filteredPackets = filteredPackets.filter(function (packet) {
                return packet.Data.Data.destPort == dstPort;
            });
    }


    if (filteredPackets.length == 0) {
        filteredPackets = receivedPackets.filter(function (packet) {
            var firmIn1 = firmInput.value.toLowerCase();
            var firmIn2 = packet.Data.ispData.organization.toLowerCase();
            return firmIn2.includes(firmIn1);
        });
    }
    else {
        filteredPackets = filteredPackets.filter(function (packet) {
            var firmIn1 = firmInput.value.toLowerCase();
            var firmIn2 = packet.Data.ispData.organization.toLowerCase();
            return firmIn2.includes(firmIn1);
        });
    }

    if (filteredPackets.length != 0) {
        if (ValidateIPaddress(sourceIp.value))
            filteredPackets = filteredPackets.filter(function (packet) {
                return packet.Data.sourceIp == sourceIp.value;
            });
    }
    else {
        if (ValidateIPaddress(sourceIp.value))
            filteredPackets = receivedPackets.filter(function (packet) {
                return packet.Data.sourceIp == sourceIp.value;
            });
    }

    if (filteredPackets.length != 0) {
        if (ValidateIPaddress(destIp.value))
            filteredPackets = filteredPackets.filter(function (packet) {
                return packet.Data.destIp == destIp.value;
            });
    }
    else {
        if (ValidateIPaddress(destIp.value))
            filteredPackets = receivedPackets.filter(function (packet) {
                return packet.Data.destIp == destIp.value;
            });
    }

    filtered = filteredPackets.length == 0;

    sourcePort.value = srcPort;
    destPort.value = dstPort;

    filters.disabled = false;
}

//wendet die Filter an.
function ApplyFilters() {

    deleteAllRows();
    GetFilters();
    var captureBtn = document.getElementById('capture');
    captureBtn.disabled = true;
    fillTable(filteredPackets);
    captureBtn.disabled = false;


    var table = document.getElementById("packetInfos");


    var rows = table.getElementsByTagName("tr");
    for (i = 0; i < rows.length; i++) {
        var currentRow = table.rows[i];
        var createClickHandler =
            function (row, index) {
                return function () {
                    if (lastSelectedRow != -1)
                        rows[lastSelectedRow].style = lastBackColor;
                    lastBackColor = row.style.backgroundColor;
                    row.style.backgroundColor = "red";
                    lastSelectedRow = index;

                    var cell = row.getElementsByTagName("td")[0];
                    var packetId = cell.innerHTML;

                    var clickedPacket = filteredPackets[packetId - 1];
                    ShowData(clickedPacket);
                };
            };
        currentRow.onclick = createClickHandler(currentRow, i);
    }
}

//Entfernt angewandte Filter
function DeleteFilters() {

    while (filteredPackets.length > 0) {
        filteredPackets.pop();
    }
    fillTable(receivedPackets);
}

//Befüllt die Tabelle mit den angegebenen
function fillTable(packets) {
    var index = 1;
    packets.forEach(function (packet) {
        AddPacketRow(packet, index);
        index += 1;
    })
}

//Fügt eine Zeile mit den Paket-Daten und seinem Index, was die Zeilenummer darstellt
function AddPacketRow(packet, index) {

    var packetInfos = document.getElementById('packetInfos');

// Insert a row in the table at the last row
    var newRow = packetInfos.insertRow(packetInfos.rows.length);


    var nrCell = newRow.insertCell(0);
    if (index == undefined)
        nrCell.innerHTML = displayedData.length.toString();
    else nrCell.innerHTML = index.toString();

//var timeRow   = packetInfos.insertRow(packetInfos.rows.length);
    var timeCell = newRow.insertCell(1);
    timeCell.innerHTML = packet.time;

    var srcHostCell = newRow.insertCell(2);
    srcHostCell.innerHTML = packet.Data.srcHost;

//var srcMacRow   = packetInfos.insertRow(packetInfos.rows.length);
    var srcMacCell = newRow.insertCell(3);
    srcMacCell.innerHTML = packet.sourceMac;


//var srcIPRow   = packetInfos.insertRow(packetInfos.rows.length);
    var srcIPCell = newRow.insertCell(4);
    srcIPCell.innerHTML = packet.Data.sourceIp;


//var srcPortRow   = packetInfos.insertRow(packetInfos.rows.length);
    var srcPortCell = newRow.insertCell(5);
    srcPortCell.innerHTML = packet.Data.Data.sourcePort;

    var destHostCell = newRow.insertCell(6);
    destHostCell.innerHTML = packet.Data.destHost;

//var destMacRow   = packetInfos.insertRow(packetInfos.rows.length);
    var destMacCell = newRow.insertCell(7);
    destMacCell.innerHTML = packet.destMac;


//var destIPRow   = packetInfos.insertRow(packetInfos.rows.length);
    var destIPCell = newRow.insertCell(8);
    destIPCell.innerHTML = packet.Data.destIp;


//var destPortRow   = packetInfos.insertRow(packetInfos.rows.length);
    var destPortCell = newRow.insertCell(9);
    destPortCell.innerHTML = packet.Data.Data.destPort;


//var protocolRow   = packetInfos.insertRow(packetInfos.rows.length);
    var protocolCell = newRow.insertCell(10);
    protocolCell.innerHTML = packet.Data.protocol == 6 ? 'TCP' : packet.Data.protocol == 17 ? 'UDP' : packet.Data.protocol == 1 ? 'ICMP' : 'Unknown';


//var totalLengthRow   = packetInfos.insertRow(packetInfos.rows.length);
    var totalLengthCell = newRow.insertCell(11);
    totalLengthCell.innerHTML = packet.totalLength;

//var firmRow   = packetInfos.insertRow(packetInfos.rows.length);
    var firmCell = newRow.insertCell(12);
    firmCell.innerHTML = packet.Data.ispData.organization;


}

//Wendet den Autocomplete-Mechanismus an
// inp : HTML-Element, worauf der Mechanismus anzuwenden ist
// arr: Liste der vorzuschlagenden Wörter
function autocomplete(inp, arr) {

    //Gibt an welches Element fokussiert ist
    var currentFocus;


    //erstellt die CallBack Methode die aufgerufen werden soll wenn in dem HTML-Element geschrieben wird
    inp.addEventListener("input", function (e) {
        var autocompleteList, b, i, val = this.value;

        //Schliesst alle eventuellen Listen mit den Werten, die vorgeschlagen werden sollen
        closeAllLists();
        if (!val) {
            return false;
        }

        currentFocus = -1;

        //Erzeugt einen DIV-Block der alle vorzuschlagenden Elemente enthalten wird
        autocompleteList = document.createElement("DIV");
        autocompleteList.setAttribute("id", this.id + "autocomplete-list");
        autocompleteList.setAttribute("class", "autocomplete-items");

        //hängt den oben erzeugten DIV-Block an das Autocomplete-Element an
        this.parentNode.appendChild(autocompleteList);

        for (i = 0; i < arr.length; i++) {

            //checkt, ob das Item mit demselben Buchstaben beginnt
            if (arr[i].substr(0, val.length).toUpperCase() == val.toUpperCase()) {

                //erstellt ein neues DIV Element für jedes entsprechende Elemente
                b = document.createElement("DIV");
                //markiert jeden entsprechenden Buchstaben fett
                b.innerHTML = "<strong>" + arr[i].substr(0, val.length) + "</strong>";
                b.innerHTML += arr[i].substr(val.length);

                //Inseriert ein Eingabefeld, das aktuelle Element behalten wird
                b.innerHTML += "<input type='hidden' value='" + arr[i] + "'>";

                //wenn ein vorgeschlagenes Element angeklickt wird
                b.addEventListener("click", function (e) {

                    //weist dem Autocomplete-Element den Wert des angeklickten Elementes
                    inp.value = this.getElementsByTagName("input")[0].value;

                    closeAllLists();
                });
                autocompleteList.appendChild(b);
            }
        }
    });
    /*execute a function presses a key on the keyboard:*/
    //Callback-Methode wenn eine Taste gedückt wird und das Autocomplete den Fokus hat
    inp.addEventListener("keydown", function (e) {
        var x = document.getElementById(this.id + "autocomplete-list");
        if (x) x = x.getElementsByTagName("div");

        //Taste für  Pfeil-Unten
        if (e.keyCode == 40) {

            currentFocus++;
            /*and and make the current item more visible:*/
            addActive(x);
        }
        //Taste für  Pfeil-Oben
        else if (e.keyCode == 38) { //up

            currentFocus--;
            /*and and make the current item more visible:*/
            addActive(x);
        }
        //Enter Taste
        else if (e.keyCode == 13) {

            e.preventDefault();
            if (currentFocus > -1) {

                //simuliert den Klick auf das fokussierte Element
                if (x) x[currentFocus].click();
            }
        }
    });

    function addActive(x) {

        if (!x) return false;
        removeActive(x);
        if (currentFocus >= x.length) currentFocus = 0;
        if (currentFocus < 0) currentFocus = (x.length - 1);
        x[currentFocus].classList.add("autocomplete-active");
    }

    function removeActive(x) {
        for (var i = 0; i < x.length; i++) {
            x[i].classList.remove("autocomplete-active");
        }
    }

    function closeAllLists(elmnt) {
        var x = document.getElementsByClassName("autocomplete-items");
        for (var i = 0; i < x.length; i++) {
            if (elmnt != x[i] && elmnt != inp) {
                x[i].parentNode.removeChild(x[i]);
            }
        }
    }

    document.addEventListener("click", function (e) {
        closeAllLists(e.target);
    });
}

/*

function ReformateDataForTreeview(dataPacket) {

    var jsonStr = "{\n\"label\": \"Ethernet-Frame\",\n\"children\": [\n";


    for (var key in dataPacket) {
        if (dataPacket.hasOwnProperty(key) && !isObject(dataPacket[key])) {

            jsonStr += GetJsonFromProperty(key, dataPacket[key]) + ",\n";
        }
    }
    var data = dataPacket.Data;
    jsonStr += GetJsonFromObject(data, "IPV4-Daten");


    jsonStr += "]\n}"
    return jsonStr;
}

function GetJsonFromObject(obj, name) {
    var jsonStr = "{\n\"label\": \"" + name + "\",\n\"children\": [\n";

    var counter = 0;
    for (var key in obj) {
        if (!isObject(obj[key])) {

            if (Object.getOwnPropertyNames(obj).length - 1 == counter && !(obj.hasOwnProperty('Data') && obj.hasOwnProperty('ispData') && obj.hasOwnProperty('geoData')))
                jsonStr += GetJsonFromProperty(key, obj[key]);
            else
                jsonStr += GetJsonFromProperty(key, obj[key]) + ",\n";
        }
    }

    //Cjeckt ob der die Eingenschaften für IPV4 objekt enthält
    if (obj.hasOwnProperty('Data') && obj.hasOwnProperty('ispData') && obj.hasOwnProperty('geoData')) {
        if (obj.protocol == 6) jsonStr += GetJsonFromObject(obj.Data, "TCP-Segment");
        else if (obj.protocol == 17) jsonStr += GetJsonFromObject(obj.Data, "UDP-Segment");
        else if (obj.protocol == 1) jsonStr += GetJsonFromObject(obj.Data, "ICMP-Segment");
        else jsonStr += GetJsonFromObject(obj.Data, "Unknown-Segment");

        var geoData = obj.geoData;
        var ispData = obj.ispData;
        jsonStr += ",\n" + GetJsonFromObject(geoData, "Geo-Daten");
        jsonStr += ",\n" + GetJsonFromObject(ispData, "ISP-Daten") + "\n";
    }

    jsonStr += "]\n}"
    return jsonStr;


}

function GetJsonFromProperty(key, value) {

    return "{\"label\": \"" + key + "\",\n\"children\": [\n{\"label\": \"" + value + "\"}\n]\n}";
}


*/

//Gibt an ob das überggebene Element ein Klassen-Objekt ist oder nicht
function isObject(obj) {
    return obj !== null && typeof obj === 'object';
}

//Validiert eine Ip-Adresse
function ValidateIPaddress(ipaddress) {
    return (/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ipaddress));

}

//Speichert Pakete-Daten, indem er dem Server die zu speichernden Pakete-Ids sendet
function SaveData() {

    var ids_ToSave = [];
    if (filtered)
        filteredPackets.forEach(function (packet) {
            ids_ToSave.push(packet.Id);
        });
    else
        receivedPackets.forEach(function (packet) {
            ids_ToSave.push(packet.Id);
        });

    var result = JSON.parse(postData(ids_ToSave, "user/packetTransfer/dataSave"));

    alert("Result : " + result.Result + "\nExecuted : " + result.Executed);

}

//Führt eine Post Anfrage an den Server aus
//data : Daten die über die Anfrage gesendet werden sollen
// pathname : Name des Pfads ( URL)
function postData(data, pathname) {
    var url = "/" + pathname;
    /*if(location.port!="")
     url = location.protocol+"//"+document.domain+":"+location.port+"/"+pathname;
    else
        url = location.protocol+"//"+document.domain+"/"+pathname;
        */

    var jsonData = JSON.stringify(data).toString();
    var poster = new XMLHttpRequest();
    poster.open("POST", url, false);
    poster.setRequestHeader('Content-Type', 'application/json');
    poster.send(jsonData);
    return poster.responseText;
}

function getData(pathname) {
    var xmlHttp = new XMLHttpRequest();
    xmlHttp.open("GET", pathname, false);
    xmlHttp.send(null);
    return xmlHttp.responseText;
}

//Alternative für Post Anfrage
function postToURL(url, values) {
    values = values || {};
    var form = createElement("form", {
        action: url,
        method: "POST",
        style: "display: none"
    });
    for (var property in values) {
        if (values.hasOwnProperty(property)) {
            var value = values[property];
            if (value instanceof Array) {
                for (var i = 0, l = value.length; i < l; i++) {
                    form.appendChild(createElement("input", {
                        type: "hidden",
                        name: property,
                        value: value[i]
                    }));
                }
            }
            else {
                form.appendChild(createElement("input", {
                    type: "hidden",
                    name: property,
                    value: value
                }));
            }
        }
    }
    document.body.appendChild(form);
    form.submit();
    form.on;
    document.body.removeChild(form);
}
