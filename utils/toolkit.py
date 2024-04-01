import requests
from bs4 import BeautifulSoup
import requests
import dns.resolver
import socket
import ssl
import whois
import datetime

def get_asn_for_url(url):
    try:
        # Resolve the URL to an IP address
        ip_address = socket.gethostbyname(url)
        # Perform WHOIS query to get ASN information
        obj = IPWhois(ip_address)
        result = obj.lookup_rdap()
        asn = result['asn']
        return asn
    except Exception as e:
        print(f"Error getting ASN for {url}: {e}")
        return None
    
    
def time_response(url):
    try:
        response = requests.get(url)
        return response.elapsed.total_seconds()
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return None


def domain_spf(domain):
    try:
        spf_records = dns.resolver.resolve(domain, "TXT")
        for record in spf_records:
            if "v=spf1" in record.to_text():
                return 1
        return 0
    except dns.resolver.NoAnswer:
        return 0
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def qty_ip_resolved(domain):
    try:
        ips = socket.gethostbyname_ex(domain)
        return len(ips[2])
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def qty_nameservers(domain):
    try:
        ns_records = dns.resolver.resolve(domain, "NS")
        return len(ns_records)
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def qty_mx_servers(domain):
    try:
        mx_records = dns.resolver.resolve(domain, "MX")
        return len(mx_records)
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def tls_ssl_certificate(domain):
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.connect((domain, 443))
            cert = s.getpeercert()
            if cert and ("subject" in cert) and ("issuer" in cert):
                return True
            else:
                return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return False


def is_shortened_url(url):
    try:
        response = requests.head(url, allow_redirects=True)
        # Check if the status code is a redirection (3xx)
        if 300 <= response.status_code < 400:
            return True
        else:
            return False
    except requests.exceptions.RequestException:
        # If an error occurs during the request, consider it as not a shortened URL
        return False


def is_domain_indexed(domain):
    try:
        # Perform a site-specific search on Google
        search_url = f"https://www.google.com/search?q=site:{domain}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
        }
        response = requests.get(search_url, headers=headers)

        # Check if the domain appears in the search results
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            search_results = soup.find_all("cite")
            for result in search_results:
                if domain in result.text:
                    return True
            return False
        else:
            print("Failed to retrieve search results.")
            return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return False


def is_url_indexed(url):
    try:
        print("Running is_url_indexed function")
        # Perform a search query for the URL on Google
        search_url = f"https://www.google.com/search?q={url}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
        }
        response = requests.get(search_url, headers=headers)

        # Check if the URL appears in the search results
        if response.status_code == 200:
            if url in response.text:
                return True
            else:
                return False
        else:
            print("Failed to retrieve search results.")
            return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return False


def time_domain_activation(domain):
    try:
        domain_info = whois.whois(domain)
        if isinstance(domain_info.creation_date, list):
            creation_date = domain_info.creation_date[0]
        else:
            creation_date = domain_info.creation_date
        return (datetime.datetime.now() - creation_date).days
    except Exception as e:
        print(f"An error occurred: {e}")
        return 0


def time_domain_expiration(domain):
    try:
        domain_info = whois.whois(domain)
        if isinstance(domain_info.expiration_date, list):
            expiration_date = domain_info.expiration_date[0]
        else:
            expiration_date = domain_info.expiration_date
        return (expiration_date - datetime.datetime.now()).days
    except Exception as e:
        print(f"An error occurred: {e}")
        return 0
