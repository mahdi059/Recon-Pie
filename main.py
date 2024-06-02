import requests
import dns.resolver
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import tldextract
import socket
import re
import whois

def get_AllLinks(url ): 
    try:
        response = requests.get(url) 
    except:
        
        pass

    soup = BeautifulSoup(response.text, 'html.parser') 

    links = [] 
    
    for link in soup.find_all('a'): 
        href = link.get('href') 

        if href.startswith('http'):

            links.append(href) 
        result = links
        
# get title (step 3...):
    for ti in links:
        try:
            response= requests.get(ti)
        except:
            pass
        soup = BeautifulSoup(response.content, 'html.parser')

        try:
            title = soup.title.string
            print("title of :", ti , "is:" , title ,  )
        except:
            pass
    print(result)
    Domains = [f"{extract.domain}.{extract.suffix}" for url in result for extract in [tldextract.extract(url)]]
    print(Domains)
    return links



def subdomain(sub_links):

    with open('62word.txt', 'r', encoding='utf-8') as file:
        keywords = file.readlines()

    keywords = [keyword.strip() for keyword in keywords]

    domain_names = [f"{extract.domain}.{extract.suffix}" for url in sub_links for extract in [tldextract.extract(url)]]

    for domain in domain_names:


        ns = dns.resolver.resolve(domain, 'NS')

        for server in ns:
            server = str(server)
            for keyword in keywords:
                try:

                    answers = dns.resolver.resolve(keyword + "." + domain, "A")
                    for ip in answers:
                        print(keyword + "." + domain + " - " + str(ip))

                except:
                    pass




def status(links):
    for url in links: 
        try:
            response_status = requests.get(url)
        except:
            pass

        if response_status.status_code == 200:
           print(f"{url}: Success!")
        elif response_status.status_code == 404:
            print(f"{url}: Page not found.")
        elif response_status.status_code == 500:
            print(f"{url}: Internal server error.")
        else:
            print(f"{url}: Unknown status code: {response_status.status_code}")
    



def ip(domain):
    Domains = [f"{extract.domain}.{extract.suffix}" for url in domain for extract in [tldextract.extract(url)]]
    for url in Domains:

        ip_address = socket.gethostbyname(url)

        print(f"The IP address of {url} is {ip_address}")




def port(domain):
    Domains = [f"{extract.domain}.{extract.suffix}" for url in domain for extract in [tldextract.extract(url)]]

    for url in Domains:

        ip = socket.gethostbyname(url)

    common_ports = [21, 22, 23, 25, 53, 80, 110, 119, 123, 143, 161, 194, 443, 445, 993, 995]

    for port in common_ports:  
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Set timeout to 1 second
        result = sock.connect_ex((ip, port))
        if result == 0:
            print("Port {} is open".format(port))
        else:
            print("Port {} is closed".format(port))
        sock.close()




def regex(domain):

  for url in domain:

    response = requests.get(url)

    if response.status_code == 200:
        html = response.text
        pattern_num = " (?:(?:(?:\\+?|00)(98))|(0))?((?:90|91|92|93|99|98)[0-9]{8})"
        pattern_email = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        emails = re.findall(pattern_email, html)
        numbers = re.findall(pattern_num, html)
        if emails:
            print("Found emails of:" , url , ":")
            for email in emails:
                print(email)
        else:
            print("No emails found of:" , url)

    if numbers:
        print("found number of :" , url ,":")

        print(numbers.group())
    else:
        print("no number found of:" , url )



def WHO(domain):

  Domains = [f"{extract.domain}.{extract.suffix}" for url in domain for extract in [tldextract.extract(url)]]

  for dm in Domains:

    if dm.endswith(".com") or dm.endswith(".org") or dm.endswith(".net") or dm.endswith(".ir"):   
        try:
            w = whois.whois(dm)
            print(w.text)  
            print(w.expiration_date)  
            print(w.creation_date)  
            print(w.updated_date)  
        except Exception as e:
            print("Error:", e)



user_url = input("Please enter the URL: ")
result = get_AllLinks(user_url )
status(result)
subdomain(result)
ip(result)
port(result)
regex(result)
WHO(result)



