import argparse
import base64
import sys
from scapy.all import *


def binary_to_ascii(binary_string):
    ascii_string = ''
    for binary_char in binary_string.split():
        ascii_string += chr(int(binary_char, 2))
    return ascii_string

def flags_to_binary(flags):
    flag_order = ['C','E','U','A','P','R','S','F']
    binary_flags = ['0'] * 8
    for flag in flags:
        if flag in flag_order:
            binary_flags[flag_order.index(flag)] = '1'
    return ''.join(binary_flags)


def main():
    if len(sys.argv) <= 2: # Adjust this number based on the number of required arguments
        print("Error: You must provide at least one argument.")
        sys.exit()
    #Create arguments necessary for script
    parser = argparse.ArgumentParser(description='Process a pcap file.')
    parser.add_argument('pcap_file', type=str, help='The pcap file to process.')
    parser.add_argument('-b', '--bin', action='store_true', help='Only show the binary print out of the flag bytes.')
    parser.add_argument('-a', '--ascii', action='store_true', help='Only show the acsii print out of the flag bytes.')
    parser.add_argument('-o', '--output', type=str, help='Output the parsed information into file provided in the argument')
    parser.add_argument('-d', '--decode', action='store_true', help='Base64 decode the ascii output')
    args = parser.parse_args()

    #read pcaps into a variable from provided file
    packets = rdpcap(args.pcap_file)
    #Initialize necessary variables
    count=0
    bin_list=[]
    ascii_list=[]
    #Parse through the packets and output the information in the specified format
    for packet in packets:
            if packet.haslayer(TCP):
                tcp_layer = packet.getlayer(TCP)
                if args.bin: 
                    
                    
                    a=flags_to_binary(tcp_layer.flags)
                    bin_list.append(a)
                    count+=1
                elif args.ascii:
                    b = binary_to_ascii(flags_to_binary(tcp_layer.flags))
                    ascii_list.append(b)
                    count+=1
                else:
                    continue
            
    output= ''
    if args.bin: 
        output = ' '.join (bin_list)
        #print(joined_bin)
        print("The number of TCP packets in the pcap was: ",count)
        if args.decode:
            print("Run program with --ascii argument instead of --bin if the output needs to be decode.")
    elif args.ascii: 
        output = ''.join (ascii_list)
        print("The number of TCP packets in the pcap was: ",count)
        #print(joined_ascii,"\n"  )
        if args.decode:
            try:
                b_64_string=base64.b64decode(output)
                output= f"The Base 64 decode text is:\n{b_64_string}"
            except:
                print("The text is not base64 encoded.")
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
    else:
        print(output)    
if __name__ == '__main__':
    main()