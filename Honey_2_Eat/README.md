# Honey_2_Eat.py

##Pre-Reqs
Honey_2_Eat does not require any modules outside the standard python library.

To download the repo:
```
git clone https://github.com/Kingviz22/CSC842.git
cd CSC842/URLs_4_Every1
./URLs_4_Every1.py
```

##Usage
Run the program on desired honeypot machine. You can customize the web server that is spun up to contain various urls or forms. 

#### Here is an example usage: 
```
#On local machine
sudo python3 Honey_2_Eat.py
```

##FAQ

** What is the purpose of Honey_2_Eat?**

For the 3rd cycle, I wrote a tool to crawl a webpage for urls and test for various vulnerabilities. So this time, I wanted to write a script to help analyze or detect various attack methods on a honeypot server. Again, this is a very basic configuration with some basic detection methods. 

Honey_2_Eat's purpose is to spin up a web server (on the local network at the moment) and capture requests sent against that endpoint. The requests are then analyzed to determine if various attack methods were used. 

**What are the future plans for the script?**

I would like to add more scenarios that could be captured, which would require the configuration of a web page/app with forms, backend dbs, etc.  

