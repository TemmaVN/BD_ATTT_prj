#!/usr/bin/env python3
import subprocess
import threading
import time
from datetime import datetime

class AdvancedNmapScanner:
    def __init__(self):
        self.windows_hosts = []
    
    def quick_network_scan(self, network):
        print(f"[{datetime.now()}] Bắt đầu quét mạng: {network}")
        
        cmd = f"nmap -T4 -F {network} -oG -"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        windows_hosts = []
        for line in result.stdout.split('\n'):
            if "Up" in line and "Ports:" in line:
                parts = line.split()
                ip = parts[1]
                
                if "135/open" in line or "139/open" in line or "445/open" in line:
                    windows_hosts.append(ip)
                    print(f"[+] Phát hiện Windows host: {ip}")
        
        self.windows_hosts = windows_hosts
        return windows_hosts
    
    def comprehensive_windows_scan(self, target_ip):
        print(f"[*] Quét toàn diện Windows: {target_ip}")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"windows_scan_{target_ip}_{timestamp}"
        
        commands = [
            f"nmap -sS -sV -O -p- {target_ip} -oN {filename}_full.txt",
            f"nmap -sU -p 53,137,138,161,445 {target_ip} -oN {filename}_udp.txt",
            f"nmap --script smb-os-discovery,smb-security-mode,smb-enum-shares {target_ip} -oN {filename}_smb.txt",
            f"nmap --script vuln {target_ip} -oN {filename}_vuln.txt"
        ]
        
        for cmd in commands:
            print(f"    Đang chạy: {cmd.split()[0]}...")
            subprocess.run(cmd, shell=True)
            time.sleep(2)
    
    def run_comprehensive_scan(self, network):
        windows_hosts = self.quick_network_scan(network)
        
        if not windows_hosts:
            print("[-] Không tìm thấy Windows host nào")
            return
        
        print(f"\n[+] Tìm thấy {len(windows_hosts)} Windows host")
        
        threads = []
        for host in windows_hosts:
            thread = threading.Thread(target=self.comprehensive_windows_scan, args=(host,))
            threads.append(thread)
            thread.start()
            time.sleep(1)  
        
        for thread in threads:
            thread.join()
        
        print(f"\n[{datetime.now()}] Hoàn thành quét toàn diện")

def main():
    your_network = "192.168.226.135/24"
    scanner = AdvancedNmapScanner()
    scanner.run_comprehensive_scan(your_network)

if __name__ == "__main__":
    main()