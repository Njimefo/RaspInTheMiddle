var allIpsSockets;
var ipSocket;
var ipRangeSocket;
var tableWrapper;
var blockedIpRanges = [];
var blockedIpAdresses = [];
var ipAdressShow = true;
var lastSelectedRow = -1;
var lastBackColor = null;
$(document).ready(function () {

    ConnectToServerAndStart();
});

function ConnectToServerAndStart() {

    allIpsSockets = io.connect('http://' + document.domain + ':' + location.port + '/ipBlocking');
    ipSocket = io.connect('http://' + document.domain + ':' + location.port + '/ipTransfer');
    ipRangeSocket = io.connect('http://' + document.domain + ':' + location.port + '/ipRangeTransfer');
    tableWrapper = document.getElementById('tableWrapper');


    allIpsSockets.on('ipRanges', function (msg) {
        var blockedIpRangesDataBase = JSON.parse(msg.ipRanges);
        blockedIpRangesDataBase.BlockedIpRanges.forEach(function (ipRange) {
            AddIpRangeRow(ipRange, blockedIpRanges.length);
            blockedIpRanges.append(ipRange);

        })
    });
    allIpsSockets.on('ipRanges', function (msg) {
        var blockedIpAdressesDataBase = JSON.parse(msg.ipRanges);

        blockedIpAdressesDataBase.BlockedIpAdresses.forEach(function (ip) {
            AddIpRow(ip, blockedIpAdresses.length);
            blockedIpAdresses.append(ip);

        })

    });
}

var RowClicked = function (index) {
    var table = document.getElementById("packetInfos");
    var rows = table.getElementsByTagName("tr");
    var row = rows[index];
    rows[lastSelectedRow].style = lastBackColor;
    lastBackColor = row.style.backgroundColor;
    row.style.backgroundColor = "red";
    lastSelectedRow = index;
}

function AddIpRow(ipData, nr) {


    if (ipAdressShow) {
        var packetInfos = document.getElementById('packetInfos');
        // Insert a row in the table at the last row
        var newRow = packetInfos.insertRow(packetInfos.rows.length);
        var nrCell = newRow.insertCell(0);
        nrCell.innerHTML = nr + 1;
        var dateCell = newRow.insertCell(1);
        dateCell.innerHTML = ipData.Date;
        var ipCell = newRow.insertCell(2);
        ipCell.innerHTML = ipData.IpAdress;
        var byCell = newRow.insertCell(3);
        byCell.innerHTML = ipData.By;
        newRow.onclick = RowClicked(nr);
    }


}

function AddIpRangeRow(ipRangeData, nr) {
    blockedIpRanges.append(ipRangeData);

    if (ipAdressShow) {
        var packetInfos = document.getElementById('packetInfos');
        // Insert a row in the table at the last row
        var newRow = packetInfos.insertRow(packetInfos.rows.length);
        var nrCell = newRow.insertCell(0);
        nrCell.innerHTML = nr + 1;
        var dateCell = newRow.insertCell(1);
        dateCell.innerHTML = ipRangeData.Date;
        var ipRangeCell = newRow.insertCell(2);
        ipRangeCell.innerHTML = ipData.IpRange;
        var byCell = newRow.insertCell(3);
        byCell.innerHTML = ipRangeData.By;
        newRow.onclick = RowClicked(nr);
    }
}

function BlockIp() {
    var IpInputBtn = document.getElementById('IpInput');

    if (ValidateIPaddress(IpInputBtn.innerText)) {
        var dataToSend = {Data: {Date: GetDateNowStr(), By: "Admin", IpAdress: IpInputBtn.innerText}};
        var path = "/iptables/ipBlocking";
        var result = postData(dataToSend, path);
        AddIpRow(dataToSend.Data);
        alert(result.Message);
    }
    else alert("Bitte überprüfen Sie Ihre Eingaben. Sie sind im falschen Format");
}

function SelectionChanged() {
    var selectorValue = document.getElementById('selector').value;
    ipAdressShow = selectorValue == "0";
    if (ipAdressShow) {
        var ipAdressBlock = document.getElementById('ipAdressBlock');
        var ipRangeBlock = document.getElementById('ipRangeBlock');
        ipAdressBlock.disabled = false;
        ipRangeBlock.disabled = true;
    }
    else {
        var ipAdressBlock = document.getElementById('ipAdressBlock');
        var ipRangeBlock = document.getElementById('ipRangeBlock');
        ipAdressBlock.disabled = true;
        ipRangeBlock.disabled = false;
    }
}

function UnblockElement() {
    if (lastSelectedRow == -1) return;
    if (ipAdressShow) {
        var table = document.getElementById("packetInfos");
        var rows = table.getElementsByTagName("tr");

        var dataToSend = {
            Data: {
                Date: rows[lastSelectedRow].getElementsByName('td')[1],
                By: rows[lastSelectedRow].getElementsByName('td')[2],
                IpAdress: rows[lastSelectedRow].getElementsByName('td')[3]
            }
        };
        var path = "iptables/ipUnBlocking";
        var result = postData(dataToSend, path);
        alert(result.Message);
    }
    else {
        var table = document.getElementById("packetInfos");
        var rows = table.getElementsByTagName("tr");

        var dataToSend = {
            Data: {
                Date: rows[lastSelectedRow].getElementsByName('td')[1],
                By: rows[lastSelectedRow].getElementsByName('td')[2],
                IpRange: rows[lastSelectedRow].getElementsByName('td')[3]
            }
        };
        var path = "iptables/ipRangeUnBlocking";
        var result = postData(dataToSend, path);
        alert(result.Message);
    }
    RemoveRowAt(lastSelectedRow);
    lastSelectedRow = -1;

}

function RemoveRowAt(index) {
    if (ipAdressShow) {
        blockedIpAdresses.splice(index, 1);
    }
    else blockedIpRanges.splice(index,1);

    fillTable();
}

function fillTable() {
    deleteAllRows();
    if (ipAdressShow) {
        var nr = 1;
        blockedIpAdresses.forEach(function (value) {
            AddIpRow(value, nr);
            nr += 1;
        })
    }
    else
    {
        var nr = 1;
        blockedIpRanges.forEach(function (value) {
            AddIpRangeRow(value, nr);
            nr += 1;
        })
    }
}

//Entfernt alle Zeilen von der Tabelle
function deleteAllRows() {
    var packetInfos = document.getElementById('packetInfos');

    while (packetInfos.rows.length > 1) {
        packetInfos.deleteRow(packetInfos.rows.length - 1);
    }
}

function BlockIpRanges() {
    var vonIp = document.getElementById('vonIp');
    var bisIp = document.getElementById('bisIp');

    if (ValidateIPaddress(bisIp.innerText) && ValidateIPaddress(vonIp.innerText) && vonIp.innerText < bisIp.innerText) {
        var dataToSend = {Data: {Date: GetDateNowStr(), By: "Admin", IpRange: vonIp + "-" + bisIp}};
        var path = "/iptables/ipRangeBlocking";
        var result = postData(dataToSend, path);
        AddIpRangeRow(dataToSend.Data);
        alert(result.Message);
    }
    else alert("Bitte überprüfen Sie Ihre Eingaben. Sie sind im falschen Format");
}

function GetDateNowStr() {
    var now = new Date();
    return (AddZero(now.getFullYear()).toString() + "-" + AddZero(now.getMonth()).toString() + "-" + AddZero(now.getDay()) + " " + AddZero(now.getHours()) + ":" + AddZero(now.getMinutes()) + ":" + AddZero(now.getSeconds())).toString();
}

function AddZero(num) {
    return (num >= 0 && num < 10) ? "0" + num : num + "";
}

//Validiert eine Ip-Adresse
function ValidateIPaddress(ipaddress) {
    return (/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ipaddress));

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