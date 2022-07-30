#!/usr/bin/env python2

###############################################
# Title: Script to relay multicast/broadcast  #
# Coder: csom@mackapaer.se                    #
# Name: csoM                                  #
# Date: 220729                                #
# Version: 0.1                                #
###############################################

import socket # To access network
import netifaces as ni # To get info about interfaces ex. all system network adapters and ip-addresses
import struct # To code data for RAW sockets
import os, sys # To get the current user and to fork process
import argparse # To read arguments
import time # To start a timer
import select # To recieve data on sockets concurrent
import re # To validate IP-address and port

# Create history list meant for storing known packets and then start timer
history = []
starttime = time.time()

def ethernet_head(raw_data):
    '''
    Function to parse the raw ethernet frame. Only takes one argument as the raw data
    It then returns the destination MAC, souce MAC and protocol
    '''
    dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
    dest_mac = ':'.join('{:02x}'.format(ord(sign)) for sign in dest)
    src_mac = ':'.join('{:02x}'.format(ord(sign)) for sign in src)
    proto = socket.htons(prototype)
    return dest_mac, src_mac, proto

def ipv4_head(raw_data, fl):
    '''
    Function to parse the raw IP packet. Takes two arguments as the raw data and the header length of the frame
    It then returns the version, header length, TTL, protocol, identifier, checksum, source ip and destination ip
    '''
    raw_data = raw_data[fl:]
    iph = struct.unpack('!B B H H H B B H 4s 4s', raw_data[0:20])
    version_header_length = iph[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ident = hex(iph[3])
    ttl = iph[5]
    proto = iph[6]
    checksum = hex(iph[7])
    src = iph[8]
    target = iph[9]
    target_ip = '.'.join('{:d}'.format(ord(sign)) for sign in target)
    src_ip = '.'.join('{:d}'.format(ord(sign)) for sign in src)
    return version, header_length, ttl, proto, ident, checksum, src_ip, target_ip

def udp_head(raw_data, fl, iphl):
    '''
    Function to parse the raw UDP segment. Takes three arguments as the raw data and the header length of the frame and the header length of the IP packet
    It then returns the source port, destinatio port, total length of segment and checksum
    '''
    raw_data = raw_data[fl+iphl:]
    srcp, destp, length, checksum = struct.unpack('! H H H H', raw_data[:8])
    sourceport = srcp
    destport = destp
    len = length
    crc = hex(checksum)
    return sourceport, destport, len, crc

def build_eth(raw_data, srcmac, destip, type=0x0800):
    '''
    Function to build raw frame. Takes four arguments as raw data, src-mac, dest-ip, type (which is default to ipv4 0x0800)
    It then returns the whole frame including ip-packet
    '''
    if typeofip(destip) == "B":
        destmac = "FF:FF:FF:FF:FF:FF"
    elif typeofip(destip) == "M":
        destmac = "01:00:5e:{:02x}:{:02x}:{:02x}".format(int(destip.split('.')[1]) & 127, int(destip.split('.')[2]) & 255, int(destip.split('.')[3]) & 255)
    dest_mac = destmac.replace(':', '').decode('hex')
    src_mac = srcmac.replace(':', '').decode('hex')
    frame_type = type
    data_to_send = struct.pack('! 6s 6s H',dest_mac,src_mac,frame_type) + raw_data

    return data_to_send

def send_raw(recv_data, interface):
    '''
    Function to send raw frame. Takes two arguments as raw data, sending interface
    '''
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    conn.bind((interface,0))
    conn.send(recv_data)
    conn.close()

def typeofip(ip):
    '''
    Function to determine if the IP address is multicast or broadcast, takes IP as argument
    It then returns (M)ulticast or (B)roadcast
    '''
    if 224 <= int(ip.split('.')[0]) <= 239:
        return 'M'
    elif ip == '255.255.255.255':
        return 'B'

def clearhist():
    '''
    Function to clear the history of known IP packets evry five seconds
    '''
    global starttime
    if (time.time() - starttime) > 5:
        del history[:]
        starttime = time.time()

def checkhist(identifier):
    '''
    Function to check history for known IP packets, takes one argument as IP identifier
    It then returns True or False
    '''
    if identifier in history:
        return True
    else:
        return False

def check_same_subnet(sourceip, intip, intmask):
    '''
    Function to compare subnets, takes three arguments as source IP, interface IP, interface Mask
    It then returns True or False
    '''
    sourcelist = [int(octett) for octett in sourceip.split('.')]
    intiplist = [int(octett) for octett in intip.split('.')]
    intmasklist = [int(octett) for octett in intmask.split('.')]

    sourcesubnet = "{}.{}.{}.{}".format(sourcelist[0] & intmasklist[0], sourcelist[1] & intmasklist[1], sourcelist[2] & intmasklist[2], sourcelist[3] & intmasklist[3])
    intsubnet = "{}.{}.{}.{}".format(intiplist[0] & intmasklist[0], intiplist[1] & intmasklist[1], intiplist[2] & intmasklist[2], intiplist[3] & intmasklist[3])

    if sourcesubnet == intsubnet:
        return True
    else:
        return False

def printmessage(data):
    '''
    Function to print relay message, takes data: [0] B/M,[1] Address,[2] From interface,[3] Via interface
    '''
    if data[0] == 'B':
        print ("Relaying broadcast address: {} from host: {} via interface: {}".format(data[1],data[2],data[3]))
    elif data[0] == 'M':
        print ("Relaying multicast address: {} from host: {} via interface: {}".format(data[1],data[2],data[3]))

def relaying(ints, adds, listens, mac=False):
    '''
    Function to relay specified network traffic between interfaces, takes three arguments [interfaces], [addresses:port], [listens] and boolean mac
    '''
    sniffs = []

    # Loop through addresses and start a RAW socket for each port on every one of them to receive raw IP-packets
    for add in adds:

        address, port = add.split(':')
        
        if typeofip(address) == 'M' or typeofip(address) == 'B':
            locals()[address + port + '_sniff'] = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            locals()[address + port + '_sniff'].setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            locals()[address + port + '_sniff'].bind((address,int(port)))
            sniffs.append(locals()[address + port + '_sniff'])
            
            print ("Adding listen address on: {}#{}".format(address,port))
        else:
            
            print ("Address entered are neither multicast nor broadcast, quiting...")
            exit(0)  

    
    for inter in listens:

        # For every interface loop through every address we want to monitor and join Multicast group 
        for add in adds:

            try:
                address, port = add.split(':')

                if typeofip(address) == 'M':
                    locals()[inter + port + '_listen'] = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                    locals()[inter + port + '_listen'].setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    locals()[inter + port + '_listen'].bind(('',int(port)))
                    
                    mreq = struct.pack("4s4s", socket.inet_aton(address), socket.inet_aton(ni.ifaddresses(inter)[ni.AF_INET][0]['addr']))

                    locals()[inter + port + '_listen'].setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                    
                    print ("Joining multicast {}#{} address on: {}".format(address,port,inter))
                elif typeofip(address) == 'B':
                    
                    pass

                else:
                    
                    print ("Address entered are neither multicast nor broadcast, quiting...")
                    exit(0)

            except Exception as e:
                print ("1: ",e)
    
    # Start infinite loop to listen to the RAW sockets and relay traffic
    while 1:

        try:

            # Create selector or multiple sockets with list of listeninterfaces appended
            r, w, x = select.select(sniffs, [], [], 1)
            
            # Loop through the list of sockets who ar ready with I/O and then parse the data
            for sniff in r:
                
                # Parse recieved data
                recv_data, host = sniff.recvfrom(65535)
                ipv4 = ipv4_head(recv_data,0)
                udp = udp_head(recv_data,0,ipv4[1])
                
                # Don't bother to send already sent traffic again
                if checkhist(ipv4[4]):
                    continue
                
                # Check if recieved Frame includes Address and port of monitored Addresses
                if ':'.join([ipv4[7], str(udp[1])]) in adds:
                    
                    # For every address that match loop through interfaces again to send out traffic
                    for interface in ints:
                        
                        # Compare source subnet to sending interface subnet and if same skip this iteration
                        if check_same_subnet(ipv4[6], ni.ifaddresses(interface)[ni.AF_INET][0]['addr'], ni.ifaddresses(interface)[ni.AF_INET][0]['netmask']):
                            continue

                        # Add a ethernet frame to the received packet and then send it
                        data_to_send = build_eth(recv_data, ni.ifaddresses(interface)[ni.AF_LINK][0]['addr'], ipv4[7])
                        send_raw(data_to_send, interface)

   
                        printmessage([typeofip(ipv4[7]), '#'.join([ipv4[7], str(udp[1])]), host[0], interface])
                    
                    # Try to clear history and at last append the identifier to history
                    clearhist()
                    history.append(ipv4[4])


            
        except KeyboardInterrupt:

                exit(0)

        except Exception as e:

                print ("2: ",e)

def main():

    ''' 
    Here starts the main program, first list available interfaces to use as choise in the interfaces argument.
    When user is root and specified at least one address and more than two interfaces we call the relayfunction.
    '''

    
    class UniqueAppendAction(argparse.Action):
        '''
        Class to make sure the input of interfaces are uniqe
        '''
        def __call__(self, parser, namespace, values, option_string=None):
            unique_values = set(values)
            setattr(namespace, self.dest, unique_values)

    class CheckIP(argparse.Action):
        '''
        Checks that the list of arguments contains IP-address and port like xxx.xxx.xxx.xxx:pppp
        '''
        def __call__(self, parser, namespace, values, option_string=None):
            for add in values:
                x = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}$",add) 
                if x == None:
                    raise argparse.ArgumentError(
                        self,
                        "You have to specify a valid ip-address and port separated by a colon"
                        + "You provided {}".format(values),
                    )
            setattr(namespace, self.dest, values)

    ints = ni.interfaces()
    parser = argparse.ArgumentParser(description='UDP multicast and broadcast relay between two or more interfaces')
    parser.add_argument('--addresses', action=CheckIP, required=True, nargs='+', help='listen addresses separated with spaces ex.(239.255.255.250:1900 255.255.255.255:30303)')
    parser.add_argument('--interfaces', action=UniqueAppendAction, required=True, nargs='+', choices=ints, help='interfaces to relay between r/w ex.(eth0 eth1 eth3...)')
    parser.add_argument('--listens', action=UniqueAppendAction, nargs='*', choices=ints, help='interfaces to relay from r ex.(eth0 eth1 eth3...)')
    parser.add_argument('--background', action='store_true', help='add argument if proccess should be run in background')
    
    args = parser.parse_args()

    if (not args.listens and (len(args.interfaces) < 2)):
        print ("You have to specify at least two interfaces to relay between...")
        return 0

    if os.getuid() != 0:
        print ("You have to be root to run this application!")
        return 0

    listens = set(args.interfaces)
    if args.listens:
        listens.update(args.listens)
        if args.listens == args.interfaces:
            print ("Please do not duplicate entrys in argument interfaces and listens...")
            return 0

    print ("Starting to relay addresses between the following interfaces...", list(listens))
    # If we want to run in background, fork the process and divert stdout to /dev/null
    if args.background:
        print ("Running in background...")
        pid = os.fork()
        if pid > 0:
            
            return 0

        os.setsid()
        f = open('/dev/null', 'w')
        sys.stdout = f

    # Start the main task of relay
    relaying(args.interfaces, args.addresses, listens)


if __name__ == '__main__':
    main()