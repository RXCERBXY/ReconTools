
import subprocess
import sys
import os
import subprocess
import platform
import re
from urllib import response

def get_search_command():
    current_os = platform.system()
    if current_os == "Windows":
        return "findstr"
    else:
        return "grep"

def clear_screen():
    current_os = platform.system()
    command = "cls" if current_os == "Windows" else "clear"
    subprocess.call(command, shell=True)


def pause():
    input("Press Enter to continue...")

def run_command(command):
    try:
        # run the command and capture output
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print("Errors:", result.stderr)
    except Exception as e:
        print("An error occurred:", e)
    pause()

# Main menu
def main_menu():
    clear_screen()
    print("===============================================")
    print("                  Recon Tools")
    print("===============================================")
    print("Current OS:", platform.system())
    print("1. Network Scanning Options")
    print("2. Lookup Options")
    print("3. Local Network Options")
    print("4. Exit")
    choice = input("Enter your choice: ")
    if choice == "1":
        scan_menu()
    elif choice == "2":
        lookup_menu()
    elif choice == "3":
        local_menu()
    elif choice == "4":
        sys.exit(0)
    else:
        print("Invalid choice, please try again.")
        pause()
        main_menu()

# Scan menu
def scan_menu():
    clear_screen()
    print("===============================================")
    print("          Network Scanning Options")
    print("===============================================")
    print("1. DNS Lookup + Cloudflare Detector")
    print("2. Zone Transfer")
    print("3. Port Scan")
    print("4. HTTP Header Grabber")
    print("5. Honeypot Detector")
    print("6. Robots.txt Scanner")
    print("7. Link Grabber")
    print("8. Traceroute")
    print("9. Grab Banners")
    print("10. Subnet Calculator")
    print("11. Sub-Domain Scanner")
    print("12. Error Based SQLi Scanner")
    print("13. Bloggers View")
    print("14. Wordpress Scan")
    print("15. Crawler")
    print("16. MX Lookup")
    print("17. Scan All")
    print("18. Back to Main Menu")
    choice = input("Enter your choice: ")
    if choice == "1":
        dns_lookup()
    elif choice == "2":
        zone_transfer()
    elif choice == "3":
        port_scan()
    elif choice == "4":
        http_header()
    elif choice == "5":
        honeypot()
    elif choice == "6":
        robots_txt()
    elif choice == "7":
        link_grabber()
    elif choice == "8":
        traceroute()
    elif choice == "9":
        grab_banners()
    elif choice == "10":
        subnet_calc()
    elif choice == "11":
        sub_domain_scanner()
    elif choice == "12":
        sql_injection_scan()
    elif choice == "13":
        bloggers_view()
    elif choice == "14":
        wordpress_scan()
    elif choice == "15":
        crawler()
    elif choice == "16":
        mx_lookup()
    elif choice == "17":
        scan_all()
    elif choice == "18":
        main_menu()
    else:
        print("Invalid choice, please try again.")
        pause()
        scan_menu()

# Lookup menu
def lookup_menu():
    clear_screen()
    print("===============================================")
    print("              Lookup Options")
    print("===============================================")
    print("1. WHOIS Lookup")
    print("2. IP Location Finder")
    print("3. Back to Main Menu")
    choice = input("Enter your choice: ")
    if choice == "1":
        whois_lookup()
    elif choice == "2":
        ip_locator()
    elif choice == "3":
        main_menu()
    else:
        print("Invalid choice, please try again.")
        pause()
        lookup_menu()

# Local network menu
def local_menu():
    clear_screen()
    print("===============================================")
    print("            Local Network Options")
    print("===============================================")
    print("1. Scan your local network")
    print("2. Back to Main Menu")
    choice = input("Enter your choice: ")
    if choice == "1":
        local_scan()
    elif choice == "2":
        main_menu()
    else:
        print("Invalid choice, please try again.")
        pause()
        local_menu()

# --- Tool Functions ---

def whois_lookup():
    domain = input("Enter the domain for WHOIS lookup: ")
    print(f"Performing WHOIS lookup for {domain}...")
    run_command(f"whois {domain}")
    lookup_menu()

def dns_lookup():
    domain = input("Enter the domain for DNS lookup: ")
    
    if domain.startswith("http://"):
        domain = domain[7:]
    elif domain.startswith("https://"):
        domain = domain[8:]
    
    print(f"Performing DNS lookup for {domain}...")
    run_command(f"nslookup {domain}")
    print("Detecting Cloudflare...")
    run_command(f"nslookup -type=txt {domain}")
    scan_menu()


def zone_transfer():
    domain = input("Enter the domain for Zone Transfer: ").strip()
    
    if domain.startswith("http://"):
        domain = domain[7:]
    elif domain.startswith("https://"):
        domain = domain[8:]
    
    domain = domain.rstrip("/\\")
    
    print(f"Attempting Zone Transfer for {domain}...")
    run_command(f"nslookup -type=any {domain}")
    scan_menu()



def port_scan():
    ip = input("Enter the IP address for port scanning: ")
    print(f"Performing port scan on {ip}...")
    run_command(f"nmap -Pn {ip}")
    scan_menu()

def http_header():
    url = input("Enter the URL to grab HTTP headers: ")
    print(f"Grabbing HTTP headers for {url}...")
    run_command(f"curl -I {url}")
    scan_menu()

def honeypot():
    ip = input("Enter the IP address to detect Honeypot: ")
    print(f"Detecting Honeypot for {ip}...")
    run_command(f"nmap -sV --script=http-enum {ip}")
    scan_menu()

def robots_txt():
    domain = input("Enter the domain to scan for robots.txt: ")
    print(f"Scanning for robots.txt on {domain}...")
    run_command(f"curl {domain}/robots.txt")
    scan_menu()

import subprocess
import platform
import re

def link_grabber():
    domain = input("Enter the domain to grab links from: ")
    print(f"Grabbing links from {domain}...")

    if not domain.startswith('http://') and not domain.startswith('https://'):
        domain = 'http://' + domain

    response = subprocess.getoutput(f"curl -s {domain}")

    links = re.findall(r'href="(http[^"]+)"', response)

    if links:
        for link in links:
            print(link)
    else:
        print("No links found.")

    pause()
    scan_menu()

 

    


def traceroute():
    target = input("Enter the domain or IP for traceroute: ")
    print(f"Performing traceroute to {target}...")
    if sys.platform.startswith("win"):
        run_command(f"tracert {target}")
    else:
        run_command(f"traceroute {target}")
    scan_menu()

def grab_banners():
    target = input("Enter the IP address to grab banners: ")
    print(f"Grabbing banners for {target}...")
    run_command(f"nmap -sV {target}")
    scan_menu()

def subnet_calc():
    subnet = input("Enter the IP address and subnet mask (e.g., 192.168.1.0/24): ")
    print(f"Calculating subnet for {subnet}...")
    run_command(f"nmap -sL {subnet}")
    scan_menu()

def sub_domain_scanner():
    domain = input("Enter the domain to scan for sub-domains: ")
    print(f"Scanning sub-domains for {domain}...")
    run_command(f"nslookup -type=ns {domain}")
    scan_menu()

def sql_injection_scan():
    url = input("Enter the URL to scan for SQL injection: ")
    print(f"Scanning for SQL injection vulnerabilities in {url}...")
    run_command(f"sqlmap -u {url} --batch --level=5 --risk=3")
    scan_menu()

def bloggers_view():
    url = input("Enter the URL to analyze: ")
    print(f"Getting HTTP response code for {url}...")
    run_command(f"curl -I {url}")
    print(f"Getting site title for {url}...")
    run_command(f"curl -s {url} | grep -i '<title>'")
    print(f"Getting Alexa ranking for {url}...")
    run_command(f"curl http://data.alexa.com/data?cli=10&dat=s&url={url} | grep '<REACH RANK='")
    print("Getting domain authority...")
    run_command(f"curl -H \"Content-Type: application/json\" -d '{{\"site\": \"{url}\"}}' https://api.moz.com/v2/metrics")
    print("Getting page authority...")
    run_command(f"curl -H \"Content-Type: application/json\" -d '{{\"site\": \"{url}\"}}' https://api.moz.com/v2/metrics")
    print(f"Extracting social links from {url}...")
    run_command(f"curl -s {url} | grep -i 'facebook.com\\|twitter.com\\|linkedin.com'")
    scan_menu()

def wordpress_scan():
    url = input("Enter the Wordpress site URL: ")
    print(f"Scanning for sensitive files on {url}...")
    run_command(f"wpscan --url {url} --enumerate vp")
    print(f"Detecting Wordpress version on {url}...")
    run_command(f"wpscan --url {url} --detect-version")
    print(f"Scanning for vulnerabilities based on detected version of {url}...")
    run_command(f"wpscan --url {url} --enumerate vp --plugins-detection aggressive")
    scan_menu()

def crawler():
    url = input("Enter the URL to crawl: ")
    print(f"Crawling {url}...")
    run_command(f"curl {url}")
    scan_menu()

def mx_lookup():
    domain = input("Enter the domain for MX lookup: ")
    print(f"Performing MX lookup for {domain}...")
    if sys.platform.startswith("win"):
        run_command(f"nslookup -type=mx {domain}")
    else:
        run_command(f"dig MX {domain}")
    scan_menu()

def local_scan():
    subnet = "192.168.1.0/24"
    print(f"Scanning local network hosts in {subnet}...")

    # 1) Ping-sweep to discover live hosts
    ping_scan = subprocess.run(
        f"nmap -sn {subnet}",
        shell=True,
        capture_output=True,
        text=True
    )
    print(ping_scan.stdout)

    # 2) Extract live IPs from the ping-scan output
    live_ips = re.findall(r"Nmap scan report for ([0-9]+(?:\.[0-9]+){3})", ping_scan.stdout)

    if not live_ips:
        print("No live hosts found.")
    else:
        print("Live hosts discovered:", ", ".join(live_ips))
        print("Performing port scan on each live host...")

        # 3) Port scan on each discovered IP
        for ip in live_ips:
            print(f"\n--- Port scan for {ip} ---")
            port_scan = subprocess.run(
                f"nmap -Pn {ip}",
                shell=True,
                capture_output=True,
                text=True
            )
            print(port_scan.stdout)

    pause()
    local_menu()

def ip_locator():
    ip = input("Enter the IP address to find its location: ")
    print(f"Finding location for {ip}...")
    run_command(f"curl ipinfo.io/{ip}")
    lookup_menu()

def scan_all():
    target = input("Enter the domain or IP for full scan: ")
    print(f"Performing full scan for {target}...")
    run_command(f"whois {target}")
    run_command(f"nslookup {target}")
    print("Detecting Cloudflare...")
    run_command(f"nslookup -type=txt {target}")
    run_command(f"nslookup -type=any {target}")
    run_command(f"nmap {target}")
    run_command(f"curl -I {target}")
    run_command(f"nmap -sV --script=http-enum {target}")
    run_command(f"curl {target}/robots.txt")
    run_command(f"curl -s {target} | grep 'href=\"http'")
    run_command(f"curl ipinfo.io/{target}")
    if sys.platform.startswith("win"):
        run_command(f"tracert {target}")
    else:
        run_command(f"traceroute {target}")
    run_command(f"nmap -sV {target}")
    run_command(f"nmap -sL {target}")
    run_command(f"nslookup -type=ns {target}")
    run_command(f"nslookup {target}")
    run_command(f"sqlmap -u {target} --batch --level=5 --risk=3")
    run_command(f"curl -I {target}")
    run_command(f"curl -s {target} | grep -i '<title>'")
    run_command(f"curl http://data.alexa.com/data?cli=10&dat=s&url={target} | grep '<REACH RANK='")
    run_command(f"curl -H \"Content-Type: application/json\" -d '{{\"site\": \"{target}\"}}' https://api.moz.com/v2/metrics")
    run_command(f"curl -H \"Content-Type: application/json\" -d '{{\"site\": \"{target}\"}}' https://api.moz.com/v2/metrics")
    run_command(f"curl -s {target} | grep -i 'facebook.com\\|twitter.com\\|linkedin.com'")
    run_command(f"wpscan --url {target} --enumerate vp")
    run_command(f"wpscan --url {target} --detect-version")
    run_command(f"wpscan --url {target} --enumerate vp --plugins-detection aggressive")
    run_command(f"curl {target}")
    run_command(f"nslookup -type=mx {target}")
    scan_menu()

def main():
    main_menu()

if __name__ == '__main__':
    main()
