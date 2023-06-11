# Flag_Finder

##Pre-Reqs
Semaphore.py requires one module to be installed:
scapy
(Both argparse and base64 come in the standard library)

Using pip: 
```
pip install scapy
```
To download the repo:
```
git clone https://github.com/Kingviz22/CSC842.git
cd CSC842/Flag_Finder
./semaphore.py
```

##Usage
There are 6 arguments to the program:
```
pcap_file: This is the name of the pcap file you want to parse through
-h, --help:                   Shows the help message and exit
-b, --bin:                    Only show the binary print out of the flag pytes 
-a, --ascii                   Only show the acsii print out of the flag bytes.
-o OUTPUT, --output OUTPUT    Output the parsed information into file provided in the argument
-d, --decode                  Base64 decode the ascii output
```

#### Here is some example usages: 

To convert TCP flags to ASCII and write the output to a file:
```
./semaphore.py pcap_file.pcap --ascii --output output.txt
```
To convert TCP flags to binary and write the output to a file:
```
./semaphore.py pcap_file.pcap --bin --output output.txt
```
To convert TCP flags to ASCII, decode as Base64, and write the output to a file:
```
./semaphore.py pcap_file.pcap --ascii --decode --output output.txt
```

##FAQ
** What is the purpose of Flag_Finder?**
I was participating in the US Cyber Games CTF competition and ran into a situation where the challenge was to find a message stored by the flags set in the packets. The set of 8 flags forms a byte of information. What I struggled with was a fast method of extracting all of those individual bytes from the 400+ packets in the capture. So I wrote this tool to help automate that extraction. 
**What are the future plans for the script?**

The purpose was to build an initial script that would parse TCP packets for the flag bits and output the desired format. This tool could be expanded to grab any necessary bytes found in a tcp packet and output in the desired format. 
