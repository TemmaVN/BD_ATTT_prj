#!/usr/bin/env python3
import nmap
import json
import datetime
import os

scanner = nmap.PortScanner()

# ========= FORMAT OUTPUT ========= #
def banner(title):
    print("\n" + "="*70)
    print(f"[+] {title}")
    print("="*70)

def pretty(data):
    print(json.dumps(data, indent=4))

# ========= 1. HOST DISCOVERY ========= #
def host_discovery(target):
    banner("HOST DISCOVERY - Phát hiện thiết bị trong mạng")
    print(f"[*] Scan mạng: {target}")

    scanner.scan(hosts=target, arguments='-sn')
    hosts = scanner.all_hosts()

    print(f"[+] Tổng số host online: {len(hosts)}")
    for h in hosts:
        print(f" - {h} ({scanner[h].state()})")

# ========= 2. BASIC PORT SCAN ========= #
def scan_basic(target):
    banner("PORT SCAN - Quét 1000 cổng phổ biến")
    scanner.scan(target, arguments='-sV')

    for proto in scanner[target].all_protocols():
        for p in scanner[target][proto].keys():
            info = scanner[target][proto][p]
            print(f" {p}/{proto} : {info['state']} | {info.get('name')} {info.get('version','')}")

# ========= 3. FULL TCP SCAN ========= #
def scan_full(target):
    banner("FULL TCP SCAN - Quét 65535 cổng")
    scanner.scan(target, arguments='-p-')

    for proto in scanner[target].all_protocols():
        for p in scanner[target][proto].keys():
            print(f" {p}/{proto} : {scanner[target][proto][p]['state']}")

# ========= 4. CUSTOM PORT SCAN ========= #
def scan_custom(target, ports):
    banner(f"CUSTOM PORT SCAN - Quét theo danh sách cổng: {ports}")
    scanner.scan(target, arguments=f"-p {ports} -sV")
    pretty(scanner[target])

# ========= 5. OS DETECTION ========= #
def detect_os(target):
    banner("OS DETECTION - Nhận diện hệ điều hành")
    scanner.scan(target, arguments='-O')

    if 'osmatch' in scanner[target]:
        pretty(scanner[target]['osmatch'])
    else:
        print("[!] Không thể xác định OS")

# ========= 6. AGGRESSIVE SCAN ========= #
def aggressive_scan(target):
    banner("AGGRESSIVE SCAN (-A) - Dò cực mạnh")
    scanner.scan(target, arguments='-A')
    pretty(scanner[target])

# ========= 7. NSE SCRIPT: HTTP TITLE ========= #
def script_http_title(target):
    banner("NSE SCRIPT - http-title")
    scanner.scan(target, arguments="--script http-title -p 80")

    if 80 in scanner[target]["tcp"] and "script" in scanner[target]["tcp"][80]:
        pretty(scanner[target]["tcp"][80]["script"])
    else:
        print("[!] Không tìm thấy script output")

# ========= 8. NSE SCRIPT: SMB VULN ========= #
def script_smb_vuln(target):
    banner("NSE SCRIPT - Kiểm tra lỗ hổng SMB (smb-vuln*)")
    scanner.scan(target, arguments="--script smb-vuln* -p 445")
    pretty(scanner[target]['tcp'][445].get("script", {}))

# ========= 9. NSE SCRIPT: SSH BRUTE ========= #
def script_ssh_brute(target):
    banner("NSE SCRIPT - ssh-brute (demo)")
    scanner.scan(target, arguments="--script ssh-brute -p 22")
    pretty(scanner[target]['tcp'][22].get("script", {}))

# ========= 10. LƯU BÁO CÁO JSON ========= #
def save_report(target):
    banner("EXPORT REPORT - Lưu báo cáo JSON")
    scanner.scan(target, arguments='-A -p-')

    fname = f"nmap_report_{target.replace('.', '_')}.json"
    with open(fname, "w") as f:
        json.dump(scanner[target], f, indent=4)

    print(f"[✔] Đã lưu báo cáo: {fname}")

# ========= MENU ========= #
def menu():
    while True:
        banner("MENU DEMO NMAP")
        print("""
1. Host discovery (quét mạng)
2. Basic scan (1000 cổng)
3. Full TCP scan (65535 cổng)
4. Custom port scan
5. OS detection
6. Aggressive scan (-A)
7. NSE: http-title
8. NSE: smb-vuln
9. NSE: ssh-brute
10. Export JSON report
0. Thoát
""")

        choice = input("Chọn chức năng: ")
        if choice == "0":
            break

        target = input("Nhập target (vd: 192.168.1.10 hoặc 192.168.1.0/24): ")

        match choice:
            case "1": host_discovery(target)
            case "2": scan_basic(target)
            case "3": scan_full(target)
            case "4":
                ports = input("Nhập port ví dụ 22,80,443: ")
                scan_custom(target, ports)
            case "5": detect_os(target)
            case "6": aggressive_scan(target)
            case "7": script_http_title(target)
            case "8": script_smb_vuln(target)
            case "9": script_ssh_brute(target)
            case "10": save_report(target)
            case _: print("Lựa chọn không hợp lệ!")

if __name__ == "__main__":
    banner("SUPER NMAP PYTHON DEMO")
    print("Thời gian:", datetime.datetime.now(), "\n")
    menu()
