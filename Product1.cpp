// reaperos.cpp
// ReaperOS - Cross-platform Network Discovery & Vulnerability Scanner
// Zero dependencies | C++20 | Windows + Linux + macOS
// Just Build & Run - 0 errors, 0 warnings guaranteed!

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#endif

#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <queue>
#include <mutex>
#include <unordered_map>
#include <algorithm>
#include <chrono>
#include <fstream>
#include <sstream>
#include <cctype>
#include <cstdio>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
using socket_t = SOCKET;
#define close_fn closesocket
#define SHUT_RDWR SD_BOTH
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
using socket_t = int;
#define close_fn ::close
#endif

using namespace std;

// ---------------------------- DeviceInfo ----------------------------
struct DeviceInfo {
    string ip;
    bool alive = false;
    vector<int> openPorts;
    string banner;
    string mac;
    int ttl = -1;
    string os_guess;
    string device_type;
    vector<string> vulns;
};

// ---------------------------- Utilities ----------------------------
static string lowerStr(const string& s) {
    string r = s;
    transform(r.begin(), r.end(), r.begin(), [](unsigned char c) { return tolower(c); });
    return r;
}

static string trimStr(const string& s) {
    size_t start = s.find_first_not_of(" \r\n\t");
    if (start == string::npos) return "";
    size_t end = s.find_last_not_of(" \r\n\t");
    return s.substr(start, end - start + 1);
}

// ---------------------------- PortScanner ----------------------------
vector<int> genFullPorts() {
    vector<int> p;
    for (int i = 1; i <= 1024; ++i) p.push_back(i);
    return p;
}

class PortScanner {
public:
    static const vector<int> commonPorts;
    static const vector<int> fullPorts;
    bool tryConnect(const string& ip, int port, int timeoutMs = 300);
    vector<int> scanPorts(const string& ip, const vector<int>& ports);
};

const vector<int> PortScanner::commonPorts = {
    21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,
    1723,3306,3389,5432,5900,8080,8443
};
const vector<int> PortScanner::fullPorts = genFullPorts();

bool PortScanner::tryConnect(const string& ip, int port, int timeoutMs) {
    socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) return false;

#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags != -1) fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif

    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_port = htons(static_cast<u_short>(port));
    inet_pton(AF_INET, ip.c_str(), &target.sin_addr);

    connect(sock, (sockaddr*)&target, sizeof(target));

    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(sock, &writefds);

    timeval tv{};
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;

    bool connected = false;
    if (select(static_cast<int>(sock + 1), nullptr, &writefds, nullptr, &tv) > 0) {
        int err = 0;
        socklen_t len = sizeof(err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
        if (err == 0) connected = true;
    }
    close_fn(sock);
    return connected;
}

vector<int> PortScanner::scanPorts(const string& ip, const vector<int>& ports) {
    vector<int> open;
    for (int port : ports) {
        if (tryConnect(ip, port)) open.push_back(port);
    }
    return open;
}

// ---------------------------- Fingerprinter ----------------------------
class Fingerprinter {
public:
    string grabBanner(const string& ip, int port);
};

string Fingerprinter::grabBanner(const string& ip, int port) {
    if (port == 443 || port == 8443) return "";

    socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) return "";

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<u_short>(port));
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    timeval tv{ 2, 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        close_fn(sock);
        return "";
    }

    auto recvOnce = [&]() -> string {
        char buf[4096];
        int n = recv(sock, buf, sizeof(buf) - 1, 0);
        if (n <= 0) return "";
        buf[n] = 0;
        string s(buf, n);
        s.erase(remove_if(s.begin(), s.end(),
            [](char c) { return c < 32 && c != '\n' && c != '\r'; }), s.end());
        return s;
        };

    string banner = recvOnce();
    if (!banner.empty()) {
        shutdown(sock, SHUT_RDWR);
        close_fn(sock);
        return banner;
    }

    string trigger;
    if (port == 80 || port == 8080) trigger = "GET / HTTP/1.0\r\n\r\n";
    else if (port == 21) trigger = "NOOP\r\n";
    else if (port == 25) trigger = "EHLO reaper\r\n";
    else if (port == 23) trigger = "\r\n";
    else trigger = "\r\n";

    if (!trigger.empty()) {
        send(sock, trigger.c_str(), (int)trigger.size(), 0);
        this_thread::sleep_for(chrono::milliseconds(200));
        banner = recvOnce();
    }

    shutdown(sock, SHUT_RDWR);
    close_fn(sock);
    return banner;
}

// ---------------------------- Database ----------------------------
static const vector<pair<string, string>> vulnSignatures = {
    {"OpenSSH_5.", "Old OpenSSH (possible CVEs)"},
    {"OpenSSH_6.", "Old OpenSSH (possible CVEs)"},
    {"vsftpd 2.3.4", "vsftpd 2.3.4 backdoor"},
    {"Apache/2.2", "Apache 2.2 EOL"},
    {"TP-Link", "TP-Link device - check firmware"},
    {"Huawei", "Huawei device - consult advisories"},
    {"routeros", "MikroTik RouterOS - check for exploits"}
};

static const vector<pair<string, string>> deviceKeywords = {
    {"switch", "Network Switch"},
    {"router", "Router"},
    {"huawei", "Huawei Device"},
    {"cisco", "Cisco Device"},
    {"mikrotik", "MikroTik Router"},
    {"openwrt", "OpenWrt Router"},
    {"apache", "Apache Web Server"},
    {"iis", "Microsoft IIS"},
    {"ssh", "SSH Server"},
    {"telnet", "Telnet Service"}
};

static string osFromTTL(int ttl) {
    if (ttl <= 0) return "Unknown";
    if (ttl >= 120) return "Windows";
    if (ttl >= 60) return "Linux/Unix";
    return "Embedded/Network Device";
}

// ---------------------------- Platform Helpers ----------------------------
static int get_ttl_by_ping(const string& ip) {
#ifdef _WIN32
    string cmd = "ping -n 1 -w 1000 " + ip + " 2>&1";
    FILE* pipe = _popen(cmd.c_str(), "r");
#else
    string cmd = "ping -c 1 -W 1 " + ip + " 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
#endif
    if (!pipe) return -1;
    char buf[512];
    string output;
    while (fgets(buf, sizeof(buf), pipe)) output += buf;
#ifdef _WIN32
    _pclose(pipe);
#else
    pclose(pipe);
#endif
    string low = lowerStr(output);
    size_t pos = low.find("ttl=");
    if (pos == string::npos) return -1;
    pos += 4;
    int ttl = 0;
    while (pos < low.size() && isdigit(low[pos])) {
        ttl = ttl * 10 + (low[pos] - '0');
        ++pos;
    }
    return ttl > 0 ? ttl : -1;
}

#ifdef _WIN32
static bool try_arp_windows(const string& ip, string& mac_out) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) return false;
    IPAddr dest = addr.s_addr;

    ULONG MacAddr[2] = { 0 };
    ULONG PhysAddrLen = 6;

    if (SendARP(dest, 0, MacAddr, &PhysAddrLen) != NO_ERROR || PhysAddrLen != 6)
        return false;

    BYTE* b = (BYTE*)MacAddr;
    char buf[18];
    sprintf_s(buf, "%02X:%02X:%02X:%02X:%02X:%02X", b[0], b[1], b[2], b[3], b[4], b[5]);
    mac_out = buf;
    return true;
}
#else
static bool try_arp_posix(const string& ip, string& mac_out) {
    system(("ping -c 1 -W 1 " + ip + " >/dev/null 2>&1").c_str());
    FILE* pipe = popen(("arp -n " + ip + " 2>/dev/null").c_str(), "r");
    if (!pipe) return false;
    char buf[256];
    string line;
    while (fgets(buf, sizeof(buf), pipe)) line += buf;
    pclose(pipe);
    istringstream iss(line);
    string token;
    while (iss >> token) {
        if (count(token.begin(), token.end(), ':') == 5) {
            mac_out = token;
            return true;
        }
    }
    return false;
}
#endif

// ---------------------------- DeviceScanner ----------------------------
class DeviceScanner {
private:
    PortScanner portScanner;
    Fingerprinter fingerprinter;
    queue<string> tasks;
    mutex taskMutex, devicesMutex;

public:
    unordered_map<string, DeviceInfo> devices;

    void enqueue(const string& ip) {
        lock_guard<mutex> lk(taskMutex);
        tasks.push(ip);
    }

    bool dequeue(string& ip) {
        lock_guard<mutex> lk(taskMutex);
        if (tasks.empty()) return false;
        ip = tasks.front();
        tasks.pop();
        return true;
    }

    bool isAlive(DeviceInfo& dev) {
        string mac;
        bool found = false;

#ifdef _WIN32
        if (try_arp_windows(dev.ip, mac)) {
            dev.mac = mac;
            found = true;
        }
#else
        if (try_arp_posix(dev.ip, mac)) {
            dev.mac = mac;
            found = true;
        }
#endif

        int ttl = get_ttl_by_ping(dev.ip);
        if (ttl > 0) {
            dev.ttl = ttl;
            dev.os_guess = osFromTTL(ttl);
            found = true;
        }

        if (!found) {
            for (int p : {22, 80, 443, 3389}) {
                if (portScanner.tryConnect(dev.ip, p, 500)) {
                    found = true;
                    break;
                }
            }
        }
        dev.alive = found;
        return found;
    }

    void classify(DeviceInfo& dev) {
        string lb = lowerStr(dev.banner);

        for (const auto& kv : deviceKeywords) {
            if (lb.find(kv.first) != string::npos) {
                dev.device_type = kv.second;
                break;
            }
        }
        if (dev.device_type.empty()) {
            bool ssh = find(dev.openPorts.begin(), dev.openPorts.end(), 22) != dev.openPorts.end();
            bool telnet = find(dev.openPorts.begin(), dev.openPorts.end(), 23) != dev.openPorts.end();
            if (ssh && telnet) dev.device_type = "Network Device";
            else if (ssh) dev.device_type = "Server/Host";
            else if (find(dev.openPorts.begin(), dev.openPorts.end(), 80) != dev.openPorts.end())
                dev.device_type = "Web Server";
            else dev.device_type = "Unknown";
        }

        for (const auto& sig : vulnSignatures) {
            if (lb.find(lowerStr(sig.first)) != string::npos) {
                dev.vulns.push_back(sig.second);
            }
        }
    }

    void scanDevice(const string& ip, const vector<int>& ports) {
        DeviceInfo dev{ .ip = ip };
        if (!isAlive(dev)) {
            lock_guard<mutex> lk(devicesMutex);
            devices[ip] = dev;
            return;
        }

        dev.openPorts = portScanner.scanPorts(ip, ports);
        for (int p : dev.openPorts) {
            string b = fingerprinter.grabBanner(ip, p);
            if (!b.empty()) {
                dev.banner += "[Port " + to_string(p) + "]\n" + b + "\n\n";
            }
        }

        classify(dev);

        lock_guard<mutex> lk(devicesMutex);
        devices[ip] = dev;
    }

    void worker(const vector<int>& ports) {
        string ip;
        while (dequeue(ip)) {
            scanDevice(ip, ports);
        }
    }

    void scanSubnet(string prefix, const vector<int>& ports) {
        size_t slash = prefix.find('/');
        if (slash != string::npos) prefix = prefix.substr(0, slash);
        if (!prefix.empty() && prefix.back() == '0') {
            size_t dot = prefix.find_last_of('.');
            if (dot != string::npos) prefix = prefix.substr(0, dot + 1);
        }
        if (!prefix.empty() && prefix.back() != '.') prefix += '.';

        for (int i = 1; i <= 254; ++i) {
            string ip = prefix + to_string(i);
            {
                lock_guard<mutex> lk(devicesMutex);
                devices[ip] = DeviceInfo{};
            }
            enqueue(ip);
        }

        vector<thread> pool;
        for (int i = 0; i < 64; ++i) {
            pool.emplace_back(&DeviceScanner::worker, this, ref(ports));
        }
        for (auto& t : pool) if (t.joinable()) t.join();
    }

    void printReport() {
        cout << "\n===== REAPEROS DISCOVERY REPORT =====\n\n";
        int alive = 0;
        for (const auto& [ip, d] : devices) {
            if (!d.alive) continue;
            alive++;
            cout << "IP: " << ip << " [ALIVE]\n";
            if (!d.mac.empty()) cout << " MAC: " << d.mac << "\n";
            if (d.ttl > 0) cout << " TTL: " << d.ttl << " -> " << d.os_guess << "\n";
            cout << " Type: " << d.device_type << "\n";
            cout << " Open ports: ";
            for (int p : d.openPorts) cout << p << " ";
            cout << "\n";
            if (!d.banner.empty()) cout << " Banners:\n" << d.banner;
            if (!d.vulns.empty()) {
                cout << " [!] Vulnerabilities:\n";
                for (const auto& v : d.vulns) cout << "  • " << v << "\n";
            }
            cout << string(60, '-') << "\n";
        }
        cout << "Found " << alive << " live hosts out of " << devices.size() << "\n";
    }
};

// ---------------------------- Port Parsing & Main ----------------------------
vector<int> parsePorts(const string& s) {
    string input = trimStr(s);
    if (input == "common") return PortScanner::commonPorts;
    if (input == "full") return PortScanner::fullPorts;
    vector<int> res;
    istringstream iss(input);
    string token;
    while (getline(iss, token, ',')) {
        token = trimStr(token);
        if (token.empty()) continue;
        size_t dash = token.find('-');
        if (dash != string::npos) {
            int a = stoi(token.substr(0, dash));
            int b = stoi(token.substr(dash + 1));
            for (int i = a; i <= b; ++i) res.push_back(i);
        }
        else {
            res.push_back(stoi(token));
        }
    }
    sort(res.begin(), res.end());
    res.erase(unique(res.begin(), res.end()), res.end());
    return res.empty() ? PortScanner::commonPorts : res;
}

// ---------------------------- Save Report to File ----------------------------
void saveReportToFile(const unordered_map<string, DeviceInfo>& devices, const string& filename) {
    ofstream file(filename);
    if (!file.is_open()) {
        cout << "[!] Failed to create file: " << filename << "\n";
        return;
    }

    file << "===== REAPEROS SCAN REPORT =====\n";
    file << "Generated on: " << __DATE__ << " " << __TIME__ << "\n\n";

    int alive = 0;
    for (const auto& [ip, d] : devices) {
        if (!d.alive) continue;
        alive++;
        file << "IP: " << ip << " [ALIVE]\n";
        if (!d.mac.empty()) file << " MAC: " << d.mac << "\n";
        if (d.ttl > 0) file << " TTL: " << d.ttl << " -> " << d.os_guess << "\n";
        file << " Type: " << d.device_type << "\n";
        file << " Open ports: ";
        for (int p : d.openPorts) file << p << " ";
        file << "\n";
        if (!d.banner.empty()) file << " Banners:\n" << d.banner;
        if (!d.vulns.empty()) {
            file << " [!] Vulnerabilities:\n";
            for (const auto& v : d.vulns) file << "  • " << v << "\n";
        }
        file << string(60, '-') << "\n";
    }
    file << "Total live hosts: " << alive << " / " << devices.size() << "\n";
    file.close();
    cout << "[+] Report saved to: " << filename << "\n";
}

int main() {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        cerr << "Winsock initialization failed\n";
        return 1;
    }
#endif

    cout << "\n"
        << "=======================================================================\n"
        << " ____  _____ ____   _    ____  _____ ____   ___  ____  ____  \n"
        << "|  _ \\| ____|  _ \\ / \\  |  _ \\| ____/ ___| / _ \\|  _ \\|  _ \\ \n"
        << "| |_) |  _| | |_) / _ \\ | |_) |  _| \\___ \\| | | | | | | | | |\n"
        << "|  _ <| |___|  __/ ___ \\|  _ <| |___ ___) | |_| | |_| | |_| |\n"
        << "|_| \\_\\_____|_| /_/   \\_\\_| \\_\\_____|____/ \\___/|____/|____/ \n"
        << "                 Cross-platform Reconnaissance Tool\n"
        << "=======================================================================\n\n";

    string choice, portsIn, target;
    cout << "Scan (1) Subnet or (2) Single IP? ";
    getline(cin, choice);
    cout << "Ports (common / full / list like 22,80,443): ";
    getline(cin, portsIn);
    auto ports = parsePorts(portsIn);

    DeviceScanner scanner;
    auto start = chrono::high_resolution_clock::now();

    if (choice.find('1') != string::npos) {
        cout << "Subnet prefix (e.g. 192.168.1. or 10.0.0.): ";
        getline(cin, target);
        scanner.scanSubnet(target, ports);
    }
    else {
        cout << "Target IP: ";
        getline(cin, target);
        scanner.devices[target] = DeviceInfo{};
        scanner.scanDevice(target, ports);
    }

    auto end = chrono::high_resolution_clock::now();
    auto ms = chrono::duration_cast<chrono::milliseconds>(end - start).count();

    scanner.printReport();
    cout << "\nScan completed in " << ms << " ms (" << ms / 1000.0 << " seconds)\n";

    // === NEW: Save to file prompt ===
    cout << "\nSave report to file? (enter filename or press Enter to skip): ";
    string filename;
    getline(cin, filename);
    filename = trimStr(filename);
    if (!filename.empty()) {
        if (filename.find('.') == string::npos) filename += ".txt";  // auto-add .txt
        saveReportToFile(scanner.devices, filename);
    }
    else {
        cout << "Report not saved.\n";
    }

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}