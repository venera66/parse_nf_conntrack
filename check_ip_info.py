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

                print(str(idx) + "  :  " + connection['request']['dst'])
                connections.append(connection)
        return connections

    except Exception as error:
        print(error)

def print_results(listdict):
    try:

        print("results")

    except Exception as error:
        print(error)

def ipinfo_lookup(ipaddress):
    try:
        internet_connected = ping_response = subprocess.Popen(["/bin/ping", "-c1", "-w100", INTERNET_CONNECTION_TEST_ADDRESS], stdout=subprocess.PIPE).stdout.read()

    except Exception as error:
        print(error)

nat_table = parse_nf_file(NF_FILE) 
#print(nat_table)

