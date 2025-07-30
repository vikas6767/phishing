import ipaddress
import whois
from bs4 import BeautifulSoup
import urllib.request
from urllib.parse import urlparse, quote
from datetime import datetime
import time
import socket
import re
import requests
import traceback



#1. Using the IP Address
def having_ip_address(url):
  try:
    # First try to extract domain name from URL
    parsed = urlparse(url)
    domain = parsed.netloc
    if not domain:
        domain = url
    
    # Try to convert domain to IP address
    ipaddress.ip_address(domain)
    return 1
  except:
    return 0

#2. Long URL
def long_url(url):
    if len(url) < 54:
        return 0
    elif len(url) >= 54 and len(url) <= 75:
        return 1
    return 1

#3. Using URL Shortening Services "TinyURL"
def shortening_service(url):
    match=re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',url)
    if match:
        return 1
    else:
        return 0

#4. URL's having "@" Symbol
def have_at_symbol(url):
    if "@" in url:
        return 1
    return 0  

#5. Redirecting using "//"
def redirection(url):
    if "//" in url:
        pos = url.rfind('//')
        if pos > 7:
            return 1
    return 0

#6. Adding Prefix or Suffix Separated by (-) to the Domain
def prefix_suffix_seperation(url):
    if '-' in url:
        return 1
    return 0
    
#7. Sub Domain and Multi Sub Domains
def sub_domains(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        if not domain:
            domain = url
        
        domain_parts = domain.split('.')
        if len(domain_parts) <= 2:
            return 0
        elif len(domain_parts) == 3:
            return 2
        return 1
    except:
        return 0

#8. The Existence of "HTTPS" Token in the Domain Part of the URL
def https_token(url):
    match = re.search('https://|http://', url)
    if match and match.start(0) == 0:
        url = url[match.end(0):]
    match = re.search('http|https', url)
    if match:
        return 1
    else:
        return 0

#9. Age of Domain
def age_of_domain_sub(domain):
    creation_date = domain.creation_date
    expiration_date = domain.expiration_date
    if ((expiration_date is None) or (creation_date is None)):
        return 1
    elif ((type(expiration_date) is list) or (type(creation_date) is list)):
        return 2
    else:
        ageofdomain = abs((expiration_date - creation_date).days)
        if ((ageofdomain/30) < 6):
            return 1
        else:
            return 0

def age_of_domain_main(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        if not domain:
            domain = url
            
        # Remove port number if present
        domain = domain.split(':')[0]
            
        domain_name = whois.whois(domain)
        return age_of_domain_sub(domain_name)
    except Exception as e:
        print(f"Age of domain error: {e}")
        return 1

#10.DNS Record
def dns_record(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        if not domain:
            domain = url
            
        # Remove port number if present
        domain = domain.split(':')[0]
            
        domain_name = whois.whois(domain)
        return 0
    except Exception as e:
        print(f"DNS record error: {e}")
        return 1

# 11. Web traffic 
def web_traffic(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        if not domain:
            domain = url
            
        # Remove port number if present
        domain = domain.split(':')[0]
        
        encoded_url = quote(domain)
        response = urllib.request.urlopen(f"http://data.alexa.com/data?cli=10&dat=s&url={encoded_url}", timeout=5)
        soup = BeautifulSoup(response.read(), "html.parser")
        rank_element = soup.find("REACH")
        
        if rank_element and 'RANK' in rank_element.attrs:
            rank = int(rank_element['RANK'])
            if rank < 100000:
                return 1
            else:
                return 2
        return 2
    except Exception as e:
        print(f"Web traffic error: {e}")
        return 2

#12. Domain Registration Length
def domain_registration_length_sub(domain):
    expiration_date = domain.expiration_date
    today = time.strftime('%Y-%m-%d')
    today = datetime.strptime(today, '%Y-%m-%d')
    if expiration_date is None:
        return 1
    elif type(expiration_date) is list or type(today) is list :
        return 2              
    else:
        registration_length = abs((expiration_date - today).days)
        if registration_length / 365 <= 1:
            return 1
        else:
            return 0

def domain_registration_length_main(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        if not domain:
            domain = url
            
        # Remove port number if present
        domain = domain.split(':')[0]
            
        domain_name = whois.whois(domain)
        return domain_registration_length_sub(domain_name)
    except Exception as e:
        print(f"Domain registration length error: {e}")
        return 1

#13.Statical-Report Based Feature
def statistical_report(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc
        if not hostname:
            hostname = url
            
        # Check for known phishing domains
        url_match = re.search('at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
        if url_match:
            return 1
            
        # Try to get IP address
        try:
            ip_address = socket.gethostbyname(hostname)
            ip_match = re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address)
            if ip_match:
                return 1
        except:
            pass
            
        return 0
    except Exception as e:
        print(f"Statistical report error: {e}")
        return 0

#14.iFrame Redirection
def iframe_sub(response):
    try:
        if not response or response == "":
            return 1
        elif re.findall(r"[<iframe>|<frameBorder>]", response.text):
            return 0
        else:
            return 1
    except:
        return 1

def iframe_main(url):
    try:
        response = requests.get(url, timeout=5)
        return iframe_sub(response)
    except Exception as e:
        print(f"iFrame error: {e}")
        return 1

#15. Status Bar Customization 
def mouse_over_sub(response): 
    try:
        if not response or response == "":
            return 1
        elif re.findall("<script>.+onmouseover.+</script>", response.text):
            return 1
        else:
            return 0
    except:
        return 0

def mouse_over_main(url):
    try:
        response = requests.get(url, timeout=5)
        return mouse_over_sub(response)
    except Exception as e:
        print(f"Mouse over error: {e}")
        return 0

def featureExtraction(url):
    features = []
    try:
        # Address bar based features
        features.append(having_ip_address(url))
        features.append(long_url(url))
        features.append(shortening_service(url))
        features.append(have_at_symbol(url))
        features.append(redirection(url))
        features.append(prefix_suffix_seperation(url))
        features.append(sub_domains(url))
        features.append(https_token(url))
        
        # Domain based features
        features.append(age_of_domain_main(url))
        features.append(dns_record(url))
        features.append(web_traffic(url))
        features.append(domain_registration_length_main(url))
        features.append(statistical_report(url))
        
        # HTML & Javascript based features
        features.append(iframe_main(url))
        features.append(mouse_over_main(url))
        
        # Ensure all features are present
        if len(features) < 15:
            missing = 15 - len(features)
            features.extend([0] * missing)
        
        return features
    except Exception as e:
        print(f"Feature extraction error: {e}")
        print(traceback.format_exc())
        # Return default features in case of error
        return [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 1, 0, 1, 0]

