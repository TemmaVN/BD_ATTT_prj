# Bai thuc hanh nhom
## Danh sach bai
- Cac cong cu quet : nmap, metasploit, ping
- Cong cu quet lo hong: openvas, nessus
- Cong cu chan bat goi: wireshark, tshark, tcpdump
- Cong cu phat hien bat thuong va xam nhap mang snort

# Kịch bản Demo Nmap

## 1. Host Discovery

-   Ping scan: `nmap -sn <target>`
-   ARP scan: `nmap -PR <target>`
-   ICMP scan: `nmap -PE <target>`

## 2. Port Scanning

-   TCP SYN scan: `nmap -sS <target>`
-   TCP Connect scan: `nmap -sT <target>`
-   UDP scan: `nmap -sU <target>`
-   Aggressive scan: `nmap -A <target>`

## 3. Service & Version Detection

-   `nmap -sV <target>`
-   `nmap -sV --version-all <target>`

## 4. OS Detection

-   `nmap -O <target>`
-   `nmap -A <target>`

## 5. Nmap Script Engine (NSE)

-   Default scripts: `nmap -sC <target>`
-   Vuln scripts: `nmap --script vuln <target>`
-   Auth scripts: `nmap --script auth <target>`
-   Discovery scripts: `nmap --script discovery <target>`

## 6. Full Scan Example

    nmap -sS -sV -O -A --script vuln --top-ports 1000 <target>

## 7. Scan kết hợp nâng cao

-   Scan toàn bộ port:

        nmap -p- -sS <target>

-   Scan theo dải port:

        nmap -p 1-2000 <target>

## 8. Export Output

-   XML: `nmap -oX result.xml <target>`
-   Grepable: `nmap -oG result.txt <target>`
-   Normal: `nmap -oN result.txt <target>`
