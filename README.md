# ReaporOS
Single-file cross-platform network discovery &amp; vulnerability scanner (C++20)
# ReaperOS — Black Edition

**.**

- Zero dependencies  
- Pure C++20  
- Windows + Linux + macOS  
- ARP discovery + MAC resolution  
- TTL-based OS fingerprinting  
- Banner grabbing  
- Automatic vulnerability detection  
- Instant vsftpd 2.3.4 backdoor detection  
- Finds Metasploitable 2 in < 25 seconds  

Built by one person. Runs everywhere.

# Windows (Visual Studio 2022+)
Just open reaperos.cpp → Build → Run

# Linux / macOS
g++ -std=c++20 -O2 -pthread reaperos.cpp -o reaperos && ./reaperos

### Metasploitable 2 result (real output)
```text
IP: 192.168.81.132 [ALIVE]
 Open ports: 21 22 23 25 53 80 111 139 445 3306 5432 5900
 Banners:
[Port 21] 220 (vsFTPd 2.3.4)
[Port 80] Apache/2.2.8 (Ubuntu) DAV/2

 [!] Vulnerabilities:
  • vsftpd 2.3.4 backdoor
  • Apache 2.2 EOL
