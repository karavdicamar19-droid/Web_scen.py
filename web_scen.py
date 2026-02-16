import nmap
import requests
import dns.resolver
import builtwith
from bs4 import BeautifulSoup

def deep_scan(url):
    target = url.replace("https://", "").replace("http://", "").split('/')[0]
    print(f"\n[!!!] POKREĆEM TOTALNI SKEN ZA: {target} [!!!]\n" + "="*50)

    # 1. IP I DNS PODACI
    print("\n[1] IP i DNS Analiza:")
    try:
        result = dns.resolver.resolve(target, 'A')
        for val in result:
            ip = val.to_text()
            print(f" [+] IP Adresa: {ip}")
    except:
        print(" [!] Neuspešno dobavljanje IP adrese.")

    # 2. TEHNOLOGIJE (Šta pokreće sajt)
    print("\n[2] Tehnologije sajta:")
    try:
        info = builtwith.builtwith(url)
        for key, value in info.items():
            print(f" [+] {key}: {value}")
    except:
        print(" [!] Nemoguće detektovati tehnologije.")

    # 3. NMAP SKENIRANJE PORTA (Najbitnije za "slabosti")
    print("\n[3] Skeniranje otvorenih portova (Ovo može potrajati...):")
    nm = nmap.PortScanner()
    nm.scan(target, '21,22,80,443,3306,8080') # Najčešći portovi
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                state = nm[host][proto][port]['state']
                service = nm[host][proto][port]['name']
                print(f" [+] Port {port} ({service}): {state}")

    # 4. PROVERA SIGURNOSNIH ZAGLAVLJA
    print("\n[4] Provera HTTP Sigurnosti:")
    r = requests.get(url)
    headers = r.headers
    missing = []
    for h in ['Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options']:
        if h not in headers:
            missing.append(h)
    
    if missing:
        print(f" [!] SLABOST: Nedostaju kritični headeri: {missing}")
    else:
        print(" [✓] Osnovni sigurnosni headeri su prisutni.")

    print("\n" + "="*50 + "\n[✓] SKENIRANJE ZAVRŠENO.")

# TESTIRANJE
target_url = "https://example.com" # OVDE STAVI URL
deep_scan(target_url)
