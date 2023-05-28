# DNS Network Sniffer 

##Pre-Reqs
DNS_Network_Sniffer requires two modules to be installed:
requests
scapy
plyer

Using pip: 
```
pip install requests
pip install scapy
pip install plyer
```
To download the repo:
```
git clone https://github.com/Kingviz22/CSC842.git
cd CSC842/DNS_Sniffer
./DNS_Network_Sniff.py
```
##FAQ
** What is the purpose of DNS_Network_Sniff?**
This script can be utilized or customized to the end user's preferences. As its currently scripted, it reaches out to grab the current list of malicious domains from URLHaus and uses those for the compare. But if an end user's wanted to be alerted about sites such as Social media, pornography, etc..., they could compile their own list of domains to be compared to. This could be a child protection script and modified to send an email to the end user as well. 

**What are the future plans for the script?**

The purpose was to build an initial script that would sniff traffic and prompt an alert for malicious sites. I would like to modify it to be able to send an email to the end user. Doing so requires some research into how to grab the email secret without storing it on the local script. 
