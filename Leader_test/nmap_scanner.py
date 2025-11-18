#!/usr/bin/env python3
import subprocess
import json
import xml.etree.ElementTree as ET
from ipaddress import IPv4Network

class NmapScanner:
    def __init__(self, target_range):
        self.target_range = target_range
        self.results = {}
    
    def host_discovery(self):
        print(f"[*] Đang quét host trong mạng {self.target_range}")
        
        cmd = f"nmap -sn {self.target_range} -oX -"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            root = ET.fromstring(result.stdout)
            hosts = []
            
            for host in root.findall(".//host"):
                ip = host.find(".//address[@addrtype='ipv4']")
                if ip is not None:
                    host_info = {"ip": ip.get("addr")}
                    
                    mac = host.find(".//address[@addrtype='mac']")
                    if mac is not None:
                        host_info["mac"] = mac.get("addr")
                        vendor = mac.get("vendor")
                        if vendor:
                            host_info["vendor"] = vendor
                    
                    hostname = host.find(".//hostname")
                    if hostname is not None:
                        host_info["hostname"] = hostname.get("name")
                    
                    hosts.append(host_info)
            
            self.results["hosts"] = hosts
            print(f"[+] Tìm thấy {len(hosts)} host:")
            for host in hosts:
                print(f"    IP: {host['ip']} - MAC: {host.get('mac', 'N/A')}")
            
            return hosts
        else:
            print("[-] Lỗi khi quét host discovery")
            return []
    
    def port_scan(self, target_ip, ports=None):
        print(f"[*] Đang quét cổng trên {target_ip}")
        
        if ports:
            port_arg = f"-p {ports}"
        else:
            port_arg = ""
        
        cmd = f"nmap -sS -sV {port_arg} {target_ip} -oX -"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            root = ET.fromstring(result.stdout)
            port_info = []
            
            for port in root.findall(".//port"):
                port_id = port.get("portid")
                protocol = port.get("protocol")
                state = port.find("state").get("state")
                
                service_info = {"port": port_id, "protocol": protocol, "state": state}
                
                service = port.find("service")
                if service is not None:
                    service_info["name"] = service.get("name", "")
                    service_info["product"] = service.get("product", "")
                    service_info["version"] = service.get("version", "")
                
                port_info.append(service_info)
                print(f"    Port {port_id}/{protocol}: {state} - {service_info.get('name', '')}")
            
            self.results[target_ip] = port_info
            return port_info
        else:
            print(f"[-] Lỗi khi quét cổng {target_ip}")
            return []
    
    def windows_scan(self, target_ip):
        print(f"[*] Quét chuyên sâu Windows trên {target_ip}")
        
        windows_ports = "135,139,445,3389,5985,5986"
        
        cmd = f"nmap -sS -sV -sC -p {windows_ports} --script smb* {target_ip} -oX -"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            root = ET.fromstring(result.stdout)
            
            smb_info = {}
            for script in root.findall(".//script"):
                script_id = script.get("id")
                output = script.get("output", "")
                smb_info[script_id] = output
            
            print("[+] Thông tin SMB:")
            for script, output in smb_info.items():
                print(f"    {script}: {output[:100]}...")
            
            return smb_info
        else:
            print("[-] Lỗi khi quét Windows")
            return {}

def main():
    target_network = "192.168.226.135/24"
    
    scanner = NmapScanner(target_network)
    
    hosts = scanner.host_discovery()
    
    for host in hosts:
        ip = host["ip"]
        print(f"\n[*] Quét chi tiết host: {ip}")
        
        scanner.port_scan(ip, "1-1000")
        
        if "vendor" in host and "Microsoft" in host["vendor"]:
            scanner.windows_scan(ip)
    
    with open("scan_results.json", "w") as f:
        json.dump(scanner.results, f, indent=2)
    
    print(f"\n[+] Kết quả đã được lưu vào scan_results.json")

if __name__ == "__main__":
    main()