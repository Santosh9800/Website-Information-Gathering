import whois
import socket
import requests
import json
import subprocess
import dns.resolver
from datetime import datetime
import builtwith

def banner():
    print("\033[1;32m")
    print(" ███████╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███████╗██╗  ██╗")
    print(" ██╔════╝██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗██╔════╝╚██╗██╔╝")
    print(" █████╗  ███████║██╔██╗ ██║   ██║   ██║   ██║█████╗   ╚███╔╝ ")
    print(" ██╔══╝  ██╔══██║██║╚██╗██║   ██║   ██║   ██║██╔══╝   ██╔██╗ ")
    print(" ██║     ██║  ██║██║ ╚████║   ██║   ╚██████╔╝███████╗██╔╝ ██╗")
    print(" ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚══════╝╚═╝  ╚═╝")
    print("_____________________________________________________________")
    print("🔰 Created by: Santosh Chhetri")
    print("🎬 Channel: Master in White Devil")
    print("🕵️  Tool: Website Information Gathering & Vulnerability Scanner")
    print("_____________________________________________________________\n\033[0m")

def get_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"[+] IP Address: {ip}")
        return ip
    except:
        print("[-] IP not found.")
        return None

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        print("\n[+] WHOIS Information:")
        print(f"  Domain Name: {w.domain_name}")
        print(f"  Registrar: {w.registrar}")
        print(f"  Creation Date: {w.creation_date}")
        print(f"  Expiry Date: {w.expiration_date}")
        print(f"  Country: {w.country}")
    except:
        print("[-] WHOIS lookup failed.")

def dns_records(domain):
    try:
        print("\n[+] DNS Records:")
        for qtype in ['A', 'MX', 'NS', 'TXT']:
            answers = dns.resolver.resolve(domain, qtype)
            for rdata in answers:
                print(f"  {qtype}: {rdata}")
    except:
        print(f"[-] DNS record fetch failed.")

def get_headers(domain):
    try:
        res = requests.get(f"http://{domain}", timeout=10)
        print("\n[+] HTTP Headers:")
        for header, value in res.headers.items():
            print(f"  {header}: {value}")
    except:
        print("[-] Could not fetch headers.")

def tech_stack(domain):
    try:
        tech = builtwith.parse(f"http://{domain}")
        print("\n[+] Technologies Detected:")
        for key, value in tech.items():
            print(f"  {key}: {value}")
    except:
        print("[-] BuiltWith failed.")

def nmap_scan(ip):
    print("\n[+] Running Nmap scan...")
    try:
        result = subprocess.check_output(["nmap", "-sV", "--script=vuln", ip]).decode()
        print(result)
    except Exception as e:
        print(f"[-] Nmap scan failed: {e}")

def waf_check(domain):
    print("\n[+] Checking for WAF...")
    try:
        result = subprocess.check_output(["wafw00f", domain]).decode()
        print(result)
    except:
        print("[-] WAF check failed.")

def main():
    banner()
    domain = input("Enter website (example.com): ").strip()
    ip = get_ip(domain)
    whois_lookup(domain)
    dns_records(domain)
    get_headers(domain)
    tech_stack(domain)
    if ip:
        nmap_scan(ip)
    waf_check(domain)

if __name__ == "__main__":
    main()

