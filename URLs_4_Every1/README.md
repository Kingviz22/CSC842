# URLs_4_Every1

##Pre-Reqs
URLs_4_Every1 requires a few modules to be installed:
requests, sys, bs4/BeautifulSoup, (the concurrent is options)
(Both argparse and base64 come in the standard library)

Using pip: 
```
pip install * (the required modules)
```
To download the repo:
```
git clone https://github.com/Kingviz22/CSC842.git
cd CSC842/URLs_4_Every1
./URLs_4_Every1.py
```

##Usage
Run with the URL is want to crawl and test.

#### Here is an example usage: 
```
./URLs_4_Every1.py http://testphp.vulnweb.com
```

##FAQ

** What is the purpose of URLs_4_Every1?**

Again, while competing in the US Cyber Open, there were a few web app challenges that were time consuming to run multiple types of tests against. So I created this script to run a variety of web attack vector tests to determine any potential vulnerabilities that may be easy to detect. 

**What are the future plans for the script?**

I would like to add more complex methods of testing, for example DOM-based vulerabilities and different path vulnerabilities. Thus, it would turn into more of an all-in-one testing tool. 

#DISCLAIMER: DO NOT RUN AGAINST UNAUTHORIZED URLS.#
