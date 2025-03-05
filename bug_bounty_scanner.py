import requests
from bs4 import BeautifulSoup
import argparse
import sublist3r
import nmap
from urllib.parse import urlparse, urljoin

# Define SQL Injection & XSS payloads
sql_payloads = ["' OR 1=1 --", "' UNION SELECT 1,2,3 --"]
xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"]

def scan_sql_injection(url):
    """Scan for SQL Injection vulnerabilities."""
    print("\n🔍 Scanning for SQL Injection vulnerabilities...")

    # Check if the URL contains query parameters (like ?id=1)
    parsed_url = urlparse(url)
    if "?" not in url:
        print("❌ Skipping SQL Injection scan: URL does not contain parameters.")
        return False

    for payload in sql_payloads:
        # Inject payload into existing query parameters
        target_url = f"{url}{payload}"
        try:
            response = requests.get(target_url, timeout=5)
            if "error" in response.text or "SQL" in response.text:
                print(f"🚨 SQL Injection Vulnerability Found: {target_url}")
                return True
        except requests.exceptions.RequestException as e:
            print(f"❌ Request failed: {e}")
    
    print("✅ No SQL Injection detected.")
    return False

def scan_xss(url):
    """Scan for XSS vulnerabilities."""
    print("\n🔍 Scanning for XSS vulnerabilities...")

    parsed_url = urlparse(url)

    # Check if the URL has query parameters
    if "?" not in url:
        print("❌ Skipping XSS scan: URL does not contain parameters.")
        return False

    for payload in xss_payloads:
        # Properly inject XSS payload into query parameters
        target_url = f"{url}&xss={payload}" if "?" in url else f"{url}?xss={payload}"

        try:
            response = requests.get(target_url, timeout=5)
            if payload in response.text:
                print(f"🚨 XSS Vulnerability Found: {target_url}")
                return True
        except requests.exceptions.RequestException as e:
            print(f"❌ Request failed: {e}")

    print("✅ No XSS detected.")
    return False

def enumerate_subdomains(domain):
    """Find subdomains using Sublist3r."""
    print("\n🔍 Enumerating subdomains...")
    subdomains = sublist3r.main(domain, 10, savefile=None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
    if subdomains:
        print("✅ Found Subdomains:")
        for sub in subdomains:
            print(f"  - {sub}")
    else:
        print("❌ No subdomains found.")

def scan_ports(domain):
    """Scan open ports using Nmap."""
    print("\n🔍 Scanning open ports...")
    scanner = nmap.PortScanner()
    scanner.scan(domain, arguments='-F')  # Fast scan
    for host in scanner.all_hosts():
        print(f"✅ Open Ports on {host}:")
        for port, info in scanner[host]['tcp'].items():
            print(f"  - Port {port}: {info['name']} ({info['state']})")

def check_file_upload(url):
    """Check for file upload vulnerabilities."""
    print("\n🔍 Checking for file upload vulnerabilities...")
    files = {'file': ('test.txt', b'This is a test file', 'text/plain')}
    try:
        response = requests.post(url, files=files, timeout=5)
        if response.status_code in [200, 201]:
            print(f"🚨 Potential File Upload Vulnerability Found at {url}")
        else:
            print("✅ No File Upload vulnerability detected.")
    except requests.exceptions.RequestException as e:
        print(f"❌ Request failed: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enhanced Bug Bounty Scanner")
    parser.add_argument("url", nargs="?", help="Target website URL (optional)")
    parser.add_argument("--domain", help="Target domain for subdomain & port scanning")
    parser.add_argument("--upload", help="URL to test file upload vulnerability")
    
    args = parser.parse_args()

    if args.url:
        scan_sql_injection(args.url)
        scan_xss(args.url)

    if args.domain:
        enumerate_subdomains(args.domain)
        scan_ports(args.domain)

    if args.upload:
        check_file_upload(args.upload)
