# Hidden Treasure

##Pre-Reqs
Hidden_treasure.py requires 2 module to be installed:
scapy
pycryptodome
(Both argparse and base64 come in the standard library)

Using pip: 
```
pip install scapy
pip install pycryptodome
```
To download the repo:
```
git clone https://github.com/Kingviz22/CSC842.git
cd CSC842/Hidden_Treasure
./hidden_treasure.py
```

##Usage
There are 3 arguments to the program:
```
--target_ip', type=str, required=True, help='Target IP Address'
--target_port', type=int, required=True, help='Target Port'
--data', type=str, required=True, help='Data to Hide'
```

##FAQ
** What is the purpose of Hidden_Treasure?**
I was participating in the US Cyber Games CTF competition and ran into a situation where the challenge was to find a message stored in various fields in a packet. So I wanted to learn more about how that was possible. Looks like it fairly easy to set up a simple transmission with data hidden throughout fields and to incorporate encryption.

##Future
Incorporate ways of hiding the window field size to match expected values. 
Add argument to use different methods of encryption. 
