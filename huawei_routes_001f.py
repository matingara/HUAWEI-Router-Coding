#! /Library/Frameworks/Python.framework/Versions/3.8/bin/python3
#
# 2Degrees - HUAWEI - code release - Alpha 0.0.1f
#
from netmiko import ConnectHandler
from getpass import getpass
import re
import datetime

def openURTFile(fileName, usFileName):
    urtFile = open(fileName, "w")
    datetimeObject = datetime.datetime.now()
    print(datetimeObject)
    markString = ("# Generated by huawei_routes at " + str(datetimeObject) + " \n")
    print(markString)
    urtFile.write("# ==========================================================\n")
    urtFile.write("# Firewall Analyzer: Routing Table for Huawei\n")
    urtFile.write("# Firewall name: " + usFileName + "\n")
    urtFile.write("# Generated by huawei_routes $Revision: 0.10 $ May 2022\n")
    urtFile.write("# Copyright Algosec Australia and New Zealand\n")
    urtFile.write(markString)
    urtFile.write("# ==========================================================\n")
    urtFile.write("#\n")
    urtFile.write("#Routes:\n")
    return(urtFile)

def closeURTFile(fileName):
    fileName.close()
    return()

def initializeRouterInventory(location):

    routerInventory = "NONE"
    if location == "lab":
        routerInventory = \
        {"ALGOSEC-LAB" : { "brand" : "huawei", "ipAddress" : "192.168.7.40", "userId" : "admin", "password" : "Algosec1" }}

    if location == "poc":
        routerInventory = \
        {"DRT01KPR" : { "brand" : "huawei", "ipAddress" : "172.21.220.38", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP"}, 
        "DRT02KPR" : { "brand" : "huawei", "ipAddress" : "172.21.220.39", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP"},
        "MSW03KPR" : { "brand" : "huawei", "ipAddress" : "172.21.223.130", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP"}, 
        "MSW04KPR" : { "brand" : "huawei", "ipAddress" : "172.21.223.131", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP"}, 
        "EDSW01KPR" : { "brand" : "huawei", "ipAddress" : "edsw01kpr.nzc", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP"}, 
        "EDSW02KPR" : { "brand" : "huawei", "ipAddress" : "edsw02kpr.nzc", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP"}, 
        "DRT01HAM" : { "brand" : "huawei", "ipAddress" : "172.23.220.38", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP"},
        "DRT02HAM" : { "brand" : "huawei", "ipAddress" : "172.23.220.39", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP"},
        "MSW01HAM" : { "brand" : "huawei", "ipAddress" : "172.23.220.254", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP"}, 
        "MSW02HAM" : { "brand" : "huawei", "ipAddress" : "172.23.220.253", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP"}, 
        "EDSW01HAM" : { "brand" : "huawei", "ipAddress" : "edsw01ham.nzc.co.nz", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" }}

    if location == "pockpr":
        routerInventory = \
        {"DRT01KPR" : { "brand" : "huawei", "ipAddress" : "172.21.220.38", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP"}, 
        "DRT02KPR" : { "brand" : "huawei", "ipAddress" : "172.21.220.39", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP"},
        "MSW03KPR" : { "brand" : "huawei", "ipAddress" : "172.21.223.130", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP"}, 
        "MSW04KPR" : { "brand" : "huawei", "ipAddress" : "172.21.223.131", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP"}, 
        "EDSW01KPR" : { "brand" : "huawei", "ipAddress" : "edsw01kpr.nzc", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP"}, 
        "EDSW02KPR" : { "brand" : "huawei", "ipAddress" : "edsw02kpr.nzc", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" }}

    if location == "pocham":
        routerInventory = \
        {"DRT01HAM" : { "brand" : "huawei", "ipAddress" : "172.23.220.38", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP"},
        "DRT02HAM" : { "brand" : "huawei", "ipAddress" : "172.23.220.39", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP"},
        "MSW01HAM" : { "brand" : "huawei", "ipAddress" : "172.23.220.254", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP"}, 
        "MSW02HAM" : { "brand" : "huawei", "ipAddress" : "172.23.220.253", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP"}, 
        "EDSW01HAM" : { "brand" : "huawei", "ipAddress" : "edsw01ham.nzc.co.nz", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" }}

    if location == "2degrees" or location == "2d":
        routerInventory = \
        {"DRT01KPR": { "brand" : "huawei", "ipAddress" : "172.21.220.38", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "DRT02KPR": { "brand" : "huawei", "ipAddress" : "172.21.220.39", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "MSW03KPR": { "brand" : "huawei", "ipAddress" : "172.21.220.130", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "MSW04KPR": { "brand" : "huawei", "ipAddress" : "172.21.220.131", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "EDSW01KPR" : { "brand" : "huawei", "ipAddress" : "172.21.220.108", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "EDSW02KPR" : { "brand" : "huawei", "ipAddress" : "172.21.220.109", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "DRT01HAM": { "brand" : "huawei", "ipAddress" : "172.23.220.38", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "DRT02HAM": { "brand" : "huawei", "ipAddress" : "172.23.220.39", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "MSW01HAM": { "brand" : "huawei", "ipAddress" : "172.23.220.254", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "MSW02HAM": { "brand" : "huawei", "ipAddress" : "172.23.220.253", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "EDSW01HAM" : { "brand" : "huawei", "ipAddress" : "172.23.220.111", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "ASW03KPR": { "brand" : "huawei", "ipAddress" : "172.21.220.103", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "ASW04KPR": { "brand" : "huawei", "ipAddress" : "172.21.220.104", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "ASW05KPR": { "brand" : "huawei", "ipAddress" : "172.21.220.105", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "ASW06KPR": { "brand" : "huawei", "ipAddress" : "172.21.220.106", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "MSPL01KPR" : { "brand" : "huawei", "ipAddress" : "172.21.220.202", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "BRT01KPR": { "brand" : "huawei", "ipAddress" : "172.21.220.36", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "BRT02KPR": { "brand" : "huawei", "ipAddress" : "172.21.220.37", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "EBSW01KPR" : { "brand" : "huawei", "ipAddress" : "172.21.221.19", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "BBMC01KPR" : { "brand" : "huawei", "ipAddress" : "172.21.221.22", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "RRT01KPR": { "brand" : "huawei", "ipAddress" : "172.21.221.220", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "RRT02KPR": { "brand" : "huawei", "ipAddress" : "172.21.221.221", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "TRT02KPR": { "brand" : "huawei", "ipAddress" : "172.21.221.223", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "BDSWDATA01KPR" : { "brand" : "huawei", "ipAddress" : "172.21.224.165", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "BDSWMGMT01KPR" : { "brand" : "huawei", "ipAddress" : "172.21.224.166", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "MLS01KPR": { "brand" : "huawei", "ipAddress" : "172.21.224.24", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "ELSW01KPR" : { "brand" : "huawei", "ipAddress" : "172.21.226.110", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "SLS03KPR": { "brand" : "huawei", "ipAddress" : "172.21.230.123", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "CSSW01KPR" : { "brand" : "huawei", "ipAddress" : "172.21.230.15", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "CSSW02KPR" : { "brand" : "huawei", "ipAddress" : "172.21.230.16", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "SLS01KPR": { "brand" : "huawei", "ipAddress" : "172.21.230.23", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "CLS01KPR": { "brand" : "huawei", "ipAddress" : "172.21.230.26", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "PLS01KPR": { "brand" : "huawei", "ipAddress" : "172.21.231.23", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "TRT01KPR": { "brand" : "huawei", "ipAddress" : "172.21.221.222", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "ASW01HAM": { "brand" : "huawei", "ipAddress" : "172.23.220.103", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "ASW02HAM": { "brand" : "huawei", "ipAddress" : "172.23.220.104", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "BRT01HAM": { "brand" : "huawei", "ipAddress" : "172.23.220.107", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "RRT01HAM": { "brand" : "huawei", "ipAddress" : "172.23.220.220", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "RRT02HAM": { "brand" : "huawei", "ipAddress" : "172.23.220.221", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "TRT01HAM": { "brand" : "huawei", "ipAddress" : "172.23.220.222", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "TRT02HAM": { "brand" : "huawei", "ipAddress" : "172.23.220.223", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "MSPL01HAM" : { "brand" : "huawei", "ipAddress" : "172.23.220.244", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "MLS01HAM": { "brand" : "huawei", "ipAddress" : "172.23.224.108", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "ELSW01HAM" : { "brand" : "huawei", "ipAddress" : "172.23.226.110", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "SLS03HAM": { "brand" : "huawei", "ipAddress" : "172.23.230.123", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "SLS01HAM": { "brand" : "huawei", "ipAddress" : "172.23.230.23", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "CLS01HAM": { "brand" : "huawei", "ipAddress" : "172.23.230.26", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "PLS01HAM": { "brand" : "huawei", "ipAddress" : "172.23.231.23", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "EBSW01HAM" : { "brand" : "huawei", "ipAddress" : "172.23.221.19", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "BBMC01HAM" : { "brand" : "huawei", "ipAddress" : "172.23.221.22", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "ASW05HAM": { "brand" : "huawei", "ipAddress" : "172.23.221.25", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "ASW06HAM": { "brand" : "huawei", "ipAddress" : "172.23.221.26", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "CSSW01HAM" : { "brand" : "huawei", "ipAddress" : "172.23.230.15", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" },
        "CSSW02HAM" : { "brand" : "huawei", "ipAddress" : "172.23.230.16", "userId" : "Transport-AlgoSec", "password" : "Vx80BOgrOGki&c4IUn0#$JfqaxP" }}
    return(routerInventory)

def initializeInventoryKeys():
    ordinal = 1
    for dk in routerInventory.keys():
        print("dk:", ordinal, dk)
        ordinal += 1
    return

def buildRouteList(result):
    routeList = []
    parsed_result = []
    split_result = result.split("\n")
    appendMode = 'FALSE'
    for element in split_result:
        if len(element) > 1:
            print(element, len(element))
            parsed_result.append(element)
    try:
        for line in parsed_result:       
            match = re.match("^.*Destination/Mask.*$", line)
            if match:
#                print("------->", line)
#                print("matched a Route List Header", match)
                appendMode = 'TRUE'

            if appendMode == 'TRUE':
                if not match:
                    routeList.append(line)
    except:
        print("No match for Route Table Header found")
    
    print("R  O  U  T  E            L  I  S  T")
    
    for route in routeList:
        print(route, len(route))

    return(routeList)

def buildvrfList(result):
    vrfList = []
    parsed_result = []
    appendMode = "FALSE"
    split_result = result.split("\n")
    for element in split_result:
        if len(element) > 1:
            parsed_result.append(element)
    try:
        for line in parsed_result:        
            #print("------->", line)
            match = re.match("^.*VPN-Instance Name.*$", line)
            if match:
#                print("------->", line)
#                print("matched a Route List Header", match)
                appendMode = 'TRUE'
            if appendMode == 'TRUE':
                if not match:
                    vrfList.append(line)
#    for line in parsed_result:
    except:
        print("No match for VRF Table header found")

    return(vrfList)

def getVRFs(deviceType, ipAddress, userId, pwd):
    vrfList = {}
    ssh_connection = ConnectHandler(
        device_type=deviceType,
        host=ipAddress,
        username=userId,
        password=pwd,
    )
    
    try:
        print("E N T E R E D     V R F     C O D E")
        result = ssh_connection.send_command("display ip vpn-instance", delay_factor=2)
        print("result", result)
    except Exception as err:
        exception_type = type(err).__name__
        print(exception_type)
        print("getVRFs.  Unable to send command to device via ssh")
    
    vrfList = buildvrfList(result)
    return(vrfList)

def getRoutes(deviceType, ipAddress, userId, pwd):
    routeList = {}
    ssh_connection = ConnectHandler(
        device_type=deviceType,
        host=ipAddress,
        username=userId,
        password=pwd,
    )
    
    try:
        result = ssh_connection.send_command("display ip routing-table", delay_factor=2)
        print("result", result, "\n")
    except Exception as err:
        exception_type = type(err).__name__
        print(exception_type, err)
        print("getRoutes.  Unable to send command to device via ssh")
    
    routeList = buildRouteList(result)
    return(routeList)

def getRoutesInVRF(deviceType, ipAddress, userId, pwd, vrf):
    routeList = {}
    ssh_connection = ConnectHandler(
        device_type=deviceType,
        host=ipAddress,
        username=userId,
        password=pwd,
    )
    
    try:
        if vrf != 'default':
            perVRFCommand = "display ip routing-table vpn-instance " + vrf
            print("VRF Command is =", perVRFCommand)
            result = ssh_connection.send_command(perVRFCommand, delay_factor=2)
            print("result", result, "\n")
        else:
            print("D E F A U L T     S K I P P E D")
    except Exception as err:
        exception_type = type(err).__name__
        print(exception_type, err)
        print("getRoutes.  Unable to send command to device via ssh")
    
    routeList = buildRouteList(result)
    return(routeList)

def connectDevice(deviceType, ipAddress, userId, pwd):
    ssh_connection = ConnectHandler(
        device_type=deviceType,
        host=ipAddress,
        username=userId,
        password=pwd,
    )

    try:

        result_cnx = ssh_connection.send_command("screen-length 0 temporary", delay_factor=2)
        print("Connection Successful", result_cnx)
    except Exception as err:
        exception_type = type(err).__name__
        print(exception_type, err)
        print("Connection to", ipAddress, "did not work")

    return(result_cnx)

def disconnectDevice(deviceType, ipAddress, userId, pwd):
    ssh_connection = ConnectHandler(
        device_type=deviceType,
        host=ipAddress,
        username=userId,
        password=pwd,
    )
    try:
        result_dnx = ssh_connection.disconnect()
        print("Disconnection Successful", result_dnx)
    except Exception as err:
        exception_type = type(err).__name__
        print(exception_type, err)
        print("Disconnection from", ipAddress, "did not work")
    return(result_dnx)

def main():
    
    print("Executing Main Program Now. huawei_routes code. Version 0.0.1f")
    location = input("Where are we running? (lab, 2degrees, 2d, poc, pockpr, pocham [lab]):")

    if location:
        routerInventory = initializeRouterInventory(location)
    else:
        routerInventory = initializeRouterInventory("lab")

    if routerInventory:    
        for thisKey in routerInventory:
            deviceType = routerInventory[thisKey]["brand"]
            ipAddress = routerInventory[thisKey]["ipAddress"]
            userId = routerInventory[thisKey]["userId"]
            pwd = routerInventory[thisKey]["password"]
            print("Querying", deviceType, "at IP address", ipAddress, "userid", userId, "password", pwd)

            try:
                print("TRYING -> result_cnx = ssh_connection.send_command(\"screen-length 0 temporary\", delay_factor=2)")
                connectToDevice = connectDevice(deviceType, ipAddress, userId, pwd)
#                print("Route List", routeList)
            except Exception as err:
                exception_type = type(err).__name__
                print(exception_type, "\n", err)
                print("Connect = connectDevice(deviceType, ipAddress, userId, pwd) - did not work")

            try:
                routeList = getRoutes(deviceType, ipAddress, userId, pwd)
#                print("Route List", routeList)
            except Exception as err:
                exception_type = type(err).__name__
                print(exception_type, "\n", err)
                print("routeList = getRoutes(deviceType, ipAddress, userId, pwd) - did not work")
            
            try:
                vrfList = getVRFs(deviceType, ipAddress, userId, pwd)
                print("VRF List", vrfList)
                for vrf in vrfList:
                    vrf = re.sub(' +', ' ', vrf)
                    vrf = vrf.lstrip()
                    vrf = vrf.rstrip()
                    vrfFields = vrf.split(" ")
                    print("V R F     F I E L D S    ---====++++++>", vrfFields)
                    print("V R F   ---------------------------------------------------->", vrfFields[0])
                    vrfOfInterest = vrfFields[0]
                    if vrfOfInterest != 'default':
                        routesInVRF = getRoutesInVRF(deviceType, ipAddress, userId, pwd, vrfOfInterest)
                        print("routes in vrf =", routesInVRF)
                    else:
                        print("d e f a u l t    V R F     S K I P P E D")
            except Exception as err:
                exception_type = type(err).__name__
                print(exception_type, "\n", err)
                print("vrfList = getVRFs(deviceType, ipAddress, userId, pwd) - did not work")
            
            try:
                usFileName = ipAddress.replace(".","_")
                print("Creating and Opening URT File named HUAWEI_URT_" + usFileName + ".urt")
                targetURTFile = openURTFile("HUAWEI_URT_" + usFileName + ".urt", usFileName)
            except:
                print("URT File creation failed")

            try:
                ctr = ctr2 = 0
                for route in routeList:
                    ctr += 1
#                    print("Can we write a list?", targetURTFile, "------->", route)
                    editedRoute = re.sub("^ *", "", route)
                    editedRoute = re.sub('\s+'," ", editedRoute)
                    targetURTFile.write(editedRoute)
                    targetURTFile.write("\n")
                    splitEditedRoute = editedRoute.split(" ")
                    for st in splitEditedRoute:
                        if re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/', st) != None:
                            print("In LINE", ctr, "we have an IP with a slash!",st)
                targetURTFile.write("#Routes from VRFs")
                targetURTFile.write("\n")
                for route in routesInVRF:
                    ctr2 += 1
#                    print("Can we write a list?", targetURTFile, "------->", route)
                    editedRoute = re.sub("^ *", "", route)
                    editedRoute = re.sub('\s+'," ", editedRoute)
                    targetURTFile.write(editedRoute)
                    targetURTFile.write("\n")
                    splitEditedRoute = editedRoute.split(" ")
                    for st in splitEditedRoute:
                        if re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/', st) != None:
                            print("In LINE", ctr2, "we have an IP with a slash!",st)
                targetURTFile.write("#Routing Instances")
                targetURTFile.write("\n")
                for vrf in vrfList:
                    print("VRF ------->", vrf)
                    targetURTFile.write(vrf)
                    targetURTFile.write("\n")
            except:
                print("URT Write failed")

            try:
                print("Closing URT File")
                closeURTFile(targetURTFile)
            except:
                print("URT File close failed")

    print("Done.  Exiting.")
    
    exit(3535)
    
if __name__ == '__main__':
  main()

def residualCode(deviceType, ipAddress, userId, pwd):
    ssh_connection = ConnectHandler(
        device_type=deviceType,
        host=ipAddress,
        username=userId,
        password=pwd,
    )
    result_sl0 = ssh_connection.send_command("screen-length 0 temporary", delay_factor=2)
    print("result_sl0 =", result_sl0)
    #result_dsv = ssh_connection.send_command("display version", delay_factor=2)
    #print("result_dsv =", result_dsv)
    #result_dcc = ssh_connection.send_command("display current-configuration", delay_factor=2)
    #print("result_dcc =", result_dcc)
    result_irv = ssh_connection.send_command("display ip vpn-instance", delay_factor=2)
    #ctr = 0
    parsed_result = split_and_parse_result(result_irv)
    #print("LIST OF ROUTING INSTANCES =", result_irv, parsed_result)
    #result_irt = ssh_connection.send_command("display ip routing-table", delay_factor=2)
    #print("ROUTING INFORMATION =", result_irt)
    #result_iib = ssh_connection.send_command("display ip interface brief", delay_factor=2)
    #print("LIST OF INTERFACES =", result_iib)
    #result_usl = ssh_connection.send_command("undo screen-length temporary", delay_factor=2)
    #print("result_usl =", result_usl)
    #print(ssh_connection.find_prompt())
    ssh_connection.disconnect()
    return

# sampleURT():

# # ==========================================================
# # Firewall Analyzer: Routing Table for junos
# # Firewall name: 10_20_154_1
# # Generated by srx2urt $Revision: 1.13 $ Sun May 15 23:43:51 2022
# # ==========================================================
# #
# #Routes:
# 10.110.119.0	255.255.255.0	10.30.85.1	-	-
# 10.110.120.5	255.255.255.255	10.10.154.2	-	-
# #Default route
# 0.0.0.0	0.0.0.0	10.20.0.1	-	-
# #Interfaces:
# 10.10.154.1	255.255.255.0	-	reth0_0	reth0.0
# 10.50.0.49	255.255.255.252	-	st0_0	st0.0
# 10.20.154.1	255.255.0.0	-	fxp0_0	fxp0.0
# 10.20.156.1	255.255.0.0	-	fxp0_0__secondary	fxp0.0/__secondary
# 10.120.154.1	255.255.255.0	-	reth4_0	reth4.0	DMZ
# 127.0.0.0	255.255.192.0	-	10_20_154_1_backplane	10_20_154_1_backplane
# 10.110.154.1	255.255.255.0	-	reth3_0	reth3.0	DMZ
