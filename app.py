import streamlit as st
import requests
from bs4 import BeautifulSoup
import sublist3r
import nmap
from urllib.parse import urlparse

# --- CORE SCANNING LOGIC ---
sql_payloads = ["' OR 1=1 --", "' UNION SELECT 1,2,3 --"]
xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"]

def scan_sql_injection(url):
    if "?" not in url:
        return "⚠️ Skipping: URL does not contain parameters.", False
    
    for payload in sql_payloads:
        target_url = f"{url}{payload}"
        try:
            response = requests.get(target_url, timeout=5)
            if "error" in response.text or "SQL" in response.text:
                return f"🚨 SQL Injection Found: {target_url}", True
        except:
            return "❌ Request failed.", False
    return "✅ No SQL Injection detected.", False

def scan_xss(url):
    if "?" not in url:
        return "⚠️ Skipping: URL does not contain parameters.", False
    
    for payload in xss_payloads:
        target_url = f"{url}&xss={payload}" if "?" in url else f"{url}?xss={payload}"
        try:
            response = requests.get(target_url, timeout=5)
            if payload in response.text:
                return f"🚨 XSS Vulnerability Found: {target_url}", True
        except:
            return "❌ Request failed.", False
    return "✅ No XSS detected.", False

# --- STREAMLIT UI ---
st.set_page_config(page_title="CyberSentinel Scanner", page_icon="🛡️", layout="wide")

st.title("🛡️ CyberSentinel: Vulnerability Scanner")
st.markdown("Automated Reconnaissance & Web Vulnerability Testing Tool")

# Sidebar for inputs
with st.sidebar:
    st.header("Target Configuration")
    target_url = st.text_input("Target URL", placeholder="http://testphp.vulnweb.com/listproducts.php?cat=1")
    target_domain = st.text_input("Target Domain (for Subdomain/Port Scan)", placeholder="google.com")
    st.divider()
    st.info("Ensure you have permission to scan the target.")

# Tabs for different tools
tab1, tab2, tab3 = st.tabs(["🌐 Web Vulnerabilities", "🔍 Subdomain Recon", "🔌 Port Scanner"])

with tab1:
    st.header("Web Vulnerability Scanner")
    if st.button("Start Web Scan"):
        if target_url:
            with st.status("Scanning for SQLi and XSS...", expanded=True) as status:
                # SQLi
                st.write("Checking SQL Injection...")
                res_sql, found_sql = scan_sql_injection(target_url)
                if found_sql: st.error(res_sql)
                else: st.success(res_sql)
                
                # XSS
                st.write("Checking XSS...")
                res_xss, found_xss = scan_xss(target_url)
                if found_xss: st.error(res_xss)
                else: st.success(res_xss)
                
                status.update(label="Web Scan Complete!", state="complete")
        else:
            st.warning("Please enter a Target URL in the sidebar.")

with tab2:
    st.header("Subdomain Enumeration")
    if st.button("Enumerate Subdomains"):
        if target_domain:
            with st.spinner("Finding subdomains..."):
                try:
                    subdomains = sublist3r.main(target_domain, 10, savefile=None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
                    if subdomains:
                        st.write(f"✅ Found {len(subdomains)} subdomains:")
                        st.code("\n".join(subdomains))
                    else:
                        st.info("No subdomains found.")
                except Exception as e:
                    st.error(f"Error: {e}")
        else:
            st.warning("Please enter a Domain in the sidebar.")

with tab3:
    st.header("Port Scanner")
    st.warning("Note: Port scanning requires Nmap to be installed on the host system.")
    if st.button("Run Port Scan"):
        if target_domain:
            with st.spinner(f"Scanning {target_domain}..."):
                try:
                    nm = nmap.PortScanner()
                    nm.scan(target_domain, arguments='-F')
                    for host in nm.all_hosts():
                        st.write(f"### Host: {host} ({nm[host].hostname()})")
                        for proto in nm[host].all_protocols():
                            lport = nm[host][proto].keys()
                            for port in lport:
                                st.write(f"Port {port}: {nm[host][proto][port]['name']} - {nm[host][proto][port]['state']}")
                except Exception as e:
                    st.error("Nmap not found or permission denied. Port scanning is restricted on Streamlit Cloud.")
