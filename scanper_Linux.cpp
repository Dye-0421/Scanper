/*
	Name: Scanper
	Copyright: (c) M03g01d73r 2026,All Right Reverse.
	Author: _Dye_
	Date: 30/05/26 18:22 2026 
	Description: Scanner.
*/
#include<arpa/inet.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<unistd.h>
#include<netdb.h>
#include<sys/time.h>
#include<ifaddrs.h>
#include<net/if.h>
#include<thread>
#include<bits/stdc++.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<fcntl.h>
#include<signal.h>
#include<netinet/ip_icmp.h>
#include<netinet/ip.h>
using namespace std;


mutex mtx;
int portnum = 0;
int icmp_sock = -1;

string servertable(int port) {
    switch(port) {
        case 80:    return "HTTP";
        case 443:   return "HTTPS";
        case 8080:  return "HTTP-Alt";
        case 8443:  return "HTTPS-Alt";
        case 8081:  return "HTTP-Alt2";
        case 8888:  return "HTTP-Alt3";
        case 9000:  return "HTTP-Alt4";
        case 9090:  return "WebUI";
        case 10000: return "Webmin";
        case 1433:  return "MSSQL";
        case 1521:  return "Oracle";
        case 3306:  return "MySQL";
        case 5432:  return "PostgreSQL";
        case 6379:  return "Redis";
        case 27017: return "MongoDB";
        case 5984:  return "CouchDB";
        case 9042:  return "Cassandra";
        case 9200:  return "Elasticsearch";
        case 9300:  return "Elasticsearch-Transport";
        case 11211: return "Memcached";
        case 2181:  return "ZooKeeper";
        case 9092:  return "Kafka";
        case 5672:  return "RabbitMQ";
        case 61616: return "ActiveMQ";
        case 22:    return "SSH";
        case 23:    return "Telnet";
        case 3389:  return "RDP";
        case 5900:  return "VNC";
        case 5800:  return "VNC-HTTP";
        case 5901:  return "VNC-1";
        case 5902:  return "VNC-2";
        case 5500:  return "VNC-Viewer";
        case 4899:  return "Radmin";
        case 5631:  return "PCAnywhere";
        case 21:    return "FTP";
        case 69:    return "TFTP";
        case 139:   return "NetBIOS-SSN";
        case 445:   return "SMB";
        case 2049:  return "NFS";
        case 873:   return "RSYNC";
        case 548:   return "AFP";
        case 8600:  return "iSCSI";
        case 3260:  return "iSCSI-2";
        case 25:    return "SMTP";
        case 110:   return "POP3";
        case 143:   return "IMAP";
        case 465:   return "SMTPS";
        case 587:   return "SMTP-Submit";
        case 993:   return "IMAPS";
        case 995:   return "POP3S";
        case 2525:  return "SMTP-Alt";
        case 53:    return "DNS";
        case 67:    return "DHCP-Server";
        case 68:    return "DHCP-Client";
        case 5353:  return "mDNS";
        case 5355:  return "LLMNR";
        case 135:   return "MSRPC";
        case 137:   return "NetBIOS-NS";
        case 138:   return "NetBIOS-DGM";
        case 554:   return "RTSP";
        case 2869:  return "UPnP";
        case 4709:  return "NetBIOS-Alt";
        case 5357:  return "WSDAPI";
        case 49152: return "Windows-RPC";
        case 49153: return "Windows-RPC";
        case 49154: return "Windows-RPC";
        case 49155: return "Windows-RPC";
        case 49156: return "Windows-RPC";
        case 49157: return "Windows-RPC";
        case 111:   return "RPC";
        case 161:   return "SNMP";
        case 162:   return "SNMP-Trap";
        case 389:   return "LDAP";
        case 636:   return "LDAPS";
        case 514:   return "Syslog";
        case 520:   return "RIP";
        case 1080:  return "SOCKS";
        case 3128:  return "Squid";
        case 5060:  return "SIP";
        case 5061:  return "SIP-TLS";
        case 5190:  return "ICQ";
        case 2375:  return "Docker-REST";
        case 2376:  return "Docker-TLS";
        case 5000:  return "Flask/Web";
        case 8000:  return "Python-Dev";
        case 8001:  return "HTTP-Alt";
        case 8083:  return "WebUI-Alt";
        case 8883:  return "MQTT-TLS";
        case 1883:  return "MQTT";
        case 9418:  return "Git";
        case 4000:  return "GitWeb";
        case 3000:  return "Grafana/Node";
        case 3001:  return "Node-Alt";
        case 5001:  return "Python-Dev2";
        case 7000:  return "Cassandra-Alt";
        case 7001:  return "WebLogic";
        case 25565: return "Minecraft";
        case 27015: return "Steam";
        case 27016: return "Steam-Alt";
        case 9987:  return "TeamSpeak3";
        case 3478:  return "STUN";
        case 3479:  return "STUN-Alt";
        case 5222:  return "XMPP";
        case 5269:  return "XMPP-Server";
        case 1280:  return "Intel-AMT-RPC";
        case 1281:  return "Intel-AMT-RPC";
        case 1282:  return "Intel-AMT-RPC";
        case 1283:  return "Intel-AMT-RPC";
        case 1285:  return "Intel-AMT-RPC";
        case 1286:  return "Intel-AMT-RPC";
        case 1287:  return "Intel-AMT-RPC";
        case 7532:  return "Custom-Service";
        case 9999:  return "Webmin-Alt";
        case 12345: return "NetBus";
        case 31337: return "BackOrifice";
        case 6667:  return "IRC";
        case 6697:  return "IRC-SSL";
        case 50000: return "SAP";
        case 50001: return "SAP-Alt";
        case 32768: return "Linux-RPC";
        case 32769: return "Linux-RPC";
        default:    return "UNKNOW";
    }
}

string detectos(string ip) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) return "Unknown";
    
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip.c_str());
    
    char sendbuf[64];
    char recvbuf[256];
    
    struct icmphdr {
        unsigned char type;
        unsigned char code;
        unsigned short checksum;
        unsigned short id;
        unsigned short sequence;
    } *icmp = (struct icmphdr*)sendbuf;
    
    icmp->type = 8;
    icmp->code = 0;
    icmp->checksum = 0;
    icmp->id = getpid();
    icmp->sequence = 0;
    
    sendto(sock, sendbuf, 64, 0, (struct sockaddr*)&addr, sizeof(addr));
    
    socklen_t len = sizeof(addr);
    int ret = recvfrom(sock, recvbuf, 256, 0, (struct sockaddr*)&addr, &len);
    close(sock);
    
    if (ret > 0) {
        struct iphdr *ip_header = (struct iphdr*)recvbuf;
        int ttl = ip_header->ttl;
        
        if (ttl <= 64) return "Linux/macOS";
        else if (ttl <= 128) return "Windows";
        else if (ttl <= 255) return "Router";
    }
    return "Unknown OS";
}

int Pscan(int port, string ip) {
    string server = servertable(port);
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        cout << "[-]Socket Create Failed\n";
        return 0;
    }
    
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 200000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
    
    struct sockaddr_in tcp;
    tcp.sin_family = AF_INET;
    tcp.sin_addr.s_addr = inet_addr(ip.c_str());
    tcp.sin_port = htons(port);
    
    if (connect(sock, (struct sockaddr*)&tcp, sizeof(tcp)) == 0) {
        lock_guard<mutex> lock(mtx);
        cout << "[+]  " << port << "/tcp\t" << server << "\n";
        portnum++;
    }
    close(sock);
    return 1;
}

int spscan(int ps, int pe, string ip) {
    if (ps > pe) {
        swap(ps, pe);
    }
    
    cout << "[*]Target OS: " << detectos(ip) << endl;
    
    vector<thread> td;
    int maxThreads = 200;
    for (int i = ps; i <= pe; i++) {
        td.emplace_back(Pscan, i, ip);
        if ((int)td.size() >= maxThreads) {
            for (auto& t : td) t.join();
            td.clear();
        }
    }
    for (auto& t : td) t.join();
    return 0;
}

void EndTime() {
    time_t now = time(nullptr);
    struct tm* local = localtime(&now);
    cout << "\n /*Ending at :" << local->tm_year + 1900 << "-" << local->tm_mon + 1 << "-" << local->tm_mday << " " << local->tm_hour << ":" << local->tm_min << ":" << local->tm_sec << "*/\n\n";
}

void StartTime() {
    time_t now = time(nullptr);
    struct tm* local = localtime(&now);
    cout << " /*Starting at :" << local->tm_year + 1900 << "-" << local->tm_mon + 1 << "-" << local->tm_mday << " " << local->tm_hour << ":" << local->tm_min << ":" << local->tm_sec << "*/\n\n";
}

void Start() {
    cout << "_______\n";
    cout << "|\n";
    cout << "|        ______   ______     ______  ______   ______   ______\n";
    cout << "|-----|  |        |     |    |    |  |     |  |     |  |\n";
    cout << "      |  |        |     |    |    |  |     |  |_____|  |\n";
    cout << "______|  |_____   |_____|\\_  |    |  |_____|  |______  |\n";
    cout << "                                     |\n";
    cout << "                                     |\n";
    cout << "                                     |\n";
    cout << "By _Dye_,  M03g01d73r (https://www.luogu.com.cn/team/121319)\n\n\n";
}

struct p0rtscan {
    int prangestart = 1;
    int prangeend = 65535;
    int mod = 0;
    string ip = "None";
    string filename = "";
    int pscanmod = 0;
    string pingstartip, pingendip;
} t;

atomic<int> se{0};

unsigned long iptonum(string ip) {
    struct in_addr addr;
    inet_aton(ip.c_str(), &addr);
    return ntohl(addr.s_addr);
}

bool ping(string ip) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) return false;
    
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip.c_str());
    
    char sendbuf[64];
    char recvbuf[256];
    
    struct icmphdr {
        unsigned char type;
        unsigned char code;
        unsigned short checksum;
        unsigned short id;
        unsigned short sequence;
    } *icmp = (struct icmphdr*)sendbuf;
    
    icmp->type = 8;
    icmp->code = 0;
    icmp->checksum = 0;
    icmp->id = getpid();
    icmp->sequence = 0;
    
    sendto(sock, sendbuf, 64, 0, (struct sockaddr*)&addr, sizeof(addr));
    
    socklen_t len = sizeof(addr);
    int ret = recvfrom(sock, recvbuf, 256, 0, (struct sockaddr*)&addr, &len);
    close(sock);
    return ret > 0;
}

string ulToIp(unsigned long u) {
    if (u > 0xFFFFFFFF) return "";
    struct in_addr addr;
    addr.s_addr = htonl(u);
    return string(inet_ntoa(addr));
}

void scantask(string ip) {
    if (ip.empty()) return;
    if (ping(ip)) {
        lock_guard<mutex> lock(mtx);
        cout << "[+]" << ip << " host is online" << endl;
        se++;
    }
}

int pingmain(string ips, string ipe) {
    if (ips.empty() || ipe.empty()) {
        cout << "[-]Invalid IP range" << endl;
        return 1;
    }
    
    vector<thread> threads;
    auto s = iptonum(ips);
    auto e = iptonum(ipe);
    
    if (s > e) swap(s, e);
    if (e >= 0xFFFFFFFF) e = 0xFFFFFFFF;
    
    for (auto i = s; i <= e; i++) {
        if (i > 0xFFFFFFFF) break;
        string ip = ulToIp(i);
        threads.emplace_back(scantask, ip);
        
        if (threads.size() >= 64) {
            for (auto& t : threads) t.join();
            threads.clear();
        }
    }
    
    for (auto& t : threads) t.join();
    
    if (se == 0) {
        cout << "[-]No Host Were Found." << endl;
        return 1;
    }
    return 0;
}

bool pingipLess(string a, string b) {
    return iptonum(a) < iptonum(b);
}

vector<string> readLines(string& fname) {
    vector<string> ips;
    ifstream file(fname);
    if (!file.is_open()) {
        cout << "[-]Cannot open file: " << fname << endl;
        return ips;
    }
    string line;
    while (getline(file, line)) {
        size_t start = line.find_first_not_of(" \t\r\n");
        if (start == string::npos) continue;
        size_t end = line.find_last_not_of(" \t\r\n");
        string target = line.substr(start, end - start + 1);
        if (target.empty() || target[0] == '#') continue;
        ips.push_back(target);
    }
    file.close();
    return ips;
}

void filetcpscan() {
    vector<string> ips = readLines(t.filename);
    if (ips.empty()) {
        cout << "[-]No target were found." << endl;
        return;
    }
    cout << "[*]Found " << ips.size() << " targets from " << t.filename << endl;
    
    for (size_t i = 0; i < ips.size(); i++) {
        cout << "IP:" << ips[i] << endl;
        spscan(t.prangestart, t.prangeend, ips.at(i));
        cout << "\n";
    }
}

int main(int argc, char* argv[]) {
    try {
        Start();
        string version = "1.2.1EG";
        
        if (argc == 1) {
            cout << "You can try :" << argv[0] << " -h\nto know how to use.\n";
            return 0;
        } else if (strcmp(argv[1], "-v") == 0) {
            cout << "Scanper version:" << version << endl;
            cout << "Copyright (c) M03g01d73r 2026\n";
            return 0;
        } else if (strcmp(argv[1], "-h") == 0) {
            cout << "Usage:\n-v :scanper version.\nPscan & portscan: Port Scan Mod\n    tcpconnect :TCP Scan Mod\n    -i : Target ip\n    -p <start port> <end port> :Port Range\n";
            cout << "    -f <file name>:read a file and scan the target in it\n";
            cout << "Ping & PingFound <start ip> <end ip>:Ping Found Mod\n";
            cout << "Example:\n" << argv[0] << " Pscan tcpconnect -i 192.168.0.1 -p 10 100\n" << argv[0] << " Pscan tcpconnect -i 192.168.0.1\n";
            return 0;
        } else if (strcmp(argv[1], "Yuk32bits!") == 0) {
            cout << "你找到了我的彩蛋！\nyou found my egg!" << endl;
            cout << "作者中国初中生（哦我恨32位）\nThe author is a Chinese junior high school student (ugh, I hate 32-bit)" << endl;
            return 0;
        } else {
            for (int i = 2; i < argc; i++) {
                if (strcmp(argv[1], "Pscan") == 0 || strcmp(argv[1], "portscan") == 0) {
                    if (strcmp(argv[i], "-p") == 0) {
                        if (i + 2 < argc) {
                            t.prangestart = atoi(argv[i + 1]);
                            t.prangeend = atoi(argv[i + 2]);
                        }
                    } else if (strcmp(argv[i], "-i") == 0) {
                        t.ip = string(argv[i + 1]);
                        t.pscanmod = 1;
                    } else if (strcmp(argv[i], "tcpconnect") == 0) {
                        t.mod = 1;
                    } else if (strcmp(argv[i], "-f") == 0) {
                        t.pscanmod = 2;
                        t.filename = string(argv[i + 1]);
                    }
                } else if (strcmp(argv[1], "PingFound") == 0 || strcmp(argv[1], "Ping") == 0) {
                    if (argc < 4) {
                        cout << "[-]Please provide start IP and end IP" << endl;
                        return 1;
                    }
                    t.pingstartip = argv[2];
                    t.pingendip = argv[3];
                }
            }
            
            StartTime();
            if (strcmp(argv[1], "Pscan") == 0 || strcmp(argv[1], "portscan") == 0) {
                if (t.pscanmod == 0) {
                    cout << "[-][Port Scan Mod]No Target Were Found.\n";
                    EndTime();
                    return 0;
                }
                if (t.mod == 0) {
                    cout << "[-][Port Scan Mod]No Mod.\n";
                    EndTime();
                    return 0;
                } else if (t.mod == 1) {
                    if (t.pscanmod == 1) {
                        spscan(t.prangestart, t.prangeend, t.ip);
                        if (portnum == 0) {
                            cout << "[-]No Ports Were Open\n\n";
                        }
                    } else if (t.pscanmod == 2) {
                        filetcpscan();
                        if (portnum == 0) {
                            cout << "[-]No Ports Were Open\n\n";
                        }
                    }
                }
            } else if (strcmp(argv[1], "PingFound") == 0 || strcmp(argv[1], "Ping") == 0) {
                pingmain(t.pingstartip, t.pingendip);
            }
            EndTime();
            return 0;
        }
    } catch (...) {
        cout << "[-]Unknow Error.\n";
        return 1;
    }
    return 0;
}
