#!/usr/bin/python3
import shlex
import ipaddress as ipaddr
import json
from requests import get
from types import SimpleNamespace
import os
import subprocess

NF_FILE='./nf_conntrack'
INTERNET_CONNECTION_TEST_ADDRESS = '1.1.1.1'
IPINFO_URL='https://ipinfo.io/'

internet_connected = False
enriched_connections = []

#---------------Function definitions----------------------#
def check_internet_connectivity():
    global internet_connected 
    try:
        ping_result = subprocess.Popen(["/bin/ping", "-c1", "-w100", INTERNET_CONNECTION_TEST_ADDRESS], stdout=subprocess.PIPE).stdout.read()
        if ping_result:
            internet_connected = True
        else:
            internet_connected = False
    except Exception as error:
        print("Unable to run ping: \n")
        print(error)
    
def ipinfo_lookup(ipaddress):
    #Bail on private IPs
    if ipaddr.ip_address(ipaddress).is_private:
        return None
    try:
        restresult = json.loads(get(IPINFO_URL + str(ipaddress)).text)
        restresult.pop('ip', None)
        restresult.pop('readme', None)
    except Exception as error:
        print(error)
    
    return restresult

def parse_nf_file(input_file):
    try:
        connections = []
        with open(input_file, "r") as conntrack_file:
            for idx, line in enumerate(conntrack_file):
                Entry = line.strip().split() #Entry is a throwaway variable
                # print(Entry)
                #build up dictionary
                connection = dict([
                    ('network_proto', Entry[0]),
                    ('network_proto_num', Entry[1]),
                    ('tx_proto', Entry[2]),
                    ('tx_proto_num', Entry[3]),
                    ('ttl_sec', Entry[4]),
                ])
                #parse ICMP entries
                if Entry[3] == '1':
                    request = dict(kv.split("=") for kv in Entry[5:12])
                    if str(Entry[12]).find('=') != -1:
                        response = dict(kv.split("=") for kv in Entry[12:19])
                    else:
                        response = dict(kv.split("=") for kv in Entry[13:20])
                    connection['request'] = request
                    connection['response'] = response

                #parse TCP entries
                elif Entry[3] == '6':
                    connection.update({'state': Entry[5]})
                    request = dict(kv.split("=") for kv in Entry[6:12])
                    if str(Entry[12]).find('=') != -1:
                        response = dict(kv.split("=") for kv in Entry[12:18])
                    else: 
                        connection.update({'status': Entry[12]})
                        response = dict(kv.split("=") for kv in Entry[13:19])                        
                    connection['request'] = request
                    connection['response'] = response

                #parse UDP entries
                elif Entry[3] == '17':
                    request = dict(kv.split("=") for kv in Entry[5:11])
                    if str(Entry[11]).find('=') != -1:
                        response = dict(kv.split("=") for kv in Entry[11:17])
                    else: 
                        connection.update({'status': Entry[11]})
                        response = dict(kv.split("=") for kv in Entry[12:18]) 
                    connection['request'] = request
                    connection['response'] = response

                else:
                    print("Unknown protocol!")

                connections.append(connection)
        return connections

    except Exception as error:
        print(error)

def print_results(listdict):
    try:

        print("results")

    except Exception as error:
        print(error)

#----------------------------------------------------------------------#

check_internet_connectivity()
connections = parse_nf_file(NF_FILE)

if internet_connected:
    for conn in connections:
        conn.update({'request_src' : ipinfo_lookup(conn['request']['src'])})
        conn.update({'request_dst' : ipinfo_lookup(conn['request']['dst'])})
        conn.update({'response_src' : ipinfo_lookup(conn['response']['src'])})
        conn.update({'response_dst' : ipinfo_lookup(conn['response']['dst'])})
        enriched_connections.append(conn)

    print(enriched_connections)
else:
    print("Failed")