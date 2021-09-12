# Ping sweeper
# ssundell1
# 2021-09-11

import argparse
import datetime
import os
import sys

def parse_args():
    arg_parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Sweeps one or more networks for active hosts",
        epilog="""examples:
        pingsweep.py -n 192.168.0.0/24
        pingsweep.py -n 192.168.1.0/24,10.0.0.0/16
        pingsweep.py -n 192.168.1.0/24,10.0.0.0/16 -v -o pingsweep.txt"""
    )

    arg_parser.add_argument('-n', nargs='+', type=str, required=True, help='networks to scan separated by comma, e.g. 192.168.0.0/24,192.168.1.0/24')
    arg_parser.add_argument('-v', action='count', required=False, default=0, help="verbosity level, max -vvv")
    arg_parser.add_argument('-o', metavar="file", required=False, nargs='?')
    arg_parser.add_argument('-t', metavar="seconds", required=False, default=3, nargs='?', help="ping timeout")

    return arg_parser.parse_args()

def write_to_log(msg, output_file = ""):
    f = open(output_file, "a")
    f.write(msg+"\n")
    f.close()
    return

def ping(host, timeout):
    cmd = 'ping -n 1 -w '+str(timeout)+' '+host
    ping_result = os.popen(cmd).read()
    if "time=" in ping_result:
        return True
    else:
        return False
    
def get_hosts_for_network(network, verbosity):
    """
    Generates IP addresses for all hosts on a network.
    Inputs:
        network     network address, e.g. 192.168.0.0/24
        verbosity   verbosity level, 0-2
    Outputs:
        success     boolean stating fail or success
        msg         text message for information
        hosts       list with generated IP addresses
    """
    # Get netmask
    netmask = int(network.split('/')[1])
    # Get ip address of network
    ip_address = network.split('/')[0].split('.')
    # Initialize list for storing ip address bits
    bits = []
    # Split ip address into bytes
    first_byte = bin(int(ip_address[0]))
    second_byte = bin(int(ip_address[1]))
    third_byte = bin(int(ip_address[2]))
    fourth_byte = bin(int(ip_address[3]))

    bits.append(first_byte[2:])
    bits.append(second_byte[2:])
    bits.append(third_byte[2:])
    bits.append(fourth_byte[2:])

    # Fill out bytes with zeros
    bits_index = 0
    for byte in bits:
        while len(byte) < 8:
            byte = '0'+str(byte)
        bits[bits_index] = byte
        bits_index+=1

    network_bits = ''.join(bits)[0:netmask]
    host_bits = ''.join(bits)[netmask:]
    host_bits_int = int('0b'+'0'*len(host_bits),2)
    broadcast_host = '0b'+'1'*len(str(host_bits))

    hosts = []

    while int(host_bits_int) < int(broadcast_host,2)-1:
        host_bits_int = host_bits_int+1
        host_binary = network_bits+'0'*+(len(host_bits)-len(bin(host_bits_int)[2:]))+bin(host_bits_int)[2:]
        hosts.append( str(int(host_binary[0:8],2)) + '.' + str(int(host_binary[8:16],2)) + '.' + str(int(host_binary[16:24],2)) + '.' + str(int(host_binary[24:],2)) )

    return True, str(len(hosts))+" hosts on network", hosts

def main():
    args = parse_args()

    if args.n:
        networks = args.n

    if args.v:
        verbosity = args.v
        if verbosity > 2:
            verbosity = 2
    else:
        verbosity = 0

    if args.o:
        output_file = args.o
    else:
        output_file = ""

    if args.t:
        timeout = args.t
    else:
        timeout = 3

    print("::: NETWORK SCANNER :::")
    if output_file:
        write_to_log("Starting network scan "+str(datetime.datetime.now()), output_file)

    for network in networks:
        success, msg, hosts = get_hosts_for_network(network,verbosity)
        print(str(network)+": "+msg)
        for host in hosts:
            if ping(host, timeout):
                print("[+] "+host+" - up!")
                if output_file:
                    write_to_log("[+] "+host+" - up!", output_file)
            else:
                if verbosity > 0:
                    print("[ ] "+host+" - down")
                    if output_file:
                        write_to_log("[ ] "+host+" - down", output_file)

    

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)