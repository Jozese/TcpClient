
#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <string>
#include <chrono>
#include <cstring>
#include <unordered_map>
#include <locale>
#include <cstdlib>
#include <algorithm>
#include <sstream>
#include <thread>
#include <openssl/ssl.h>
#include <openssl/err.h>


#ifdef __linux__


#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

#elif _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ip2string.h>
#endif


class TcpClient {

private:
    int cSocket = -1;
    sockaddr_in sAddr;

    addrinfo *dnsResult = nullptr, *iter = nullptr;

#ifdef _WIN32
        char ipv4[INET_ADDRSTRLEN];
        WSADATA wsaData;
#endif

    std::string host;
    unsigned short port;

    SSL_CTX* sslCtx = nullptr;
    SSL* ssl = nullptr;

    bool isSsl = true;
    bool expectedSsl = true;

private:
    int ResolveDomainName();
    int SocketCreate();

public:
    TcpClient() = default;
    TcpClient(const std::string& host, unsigned short port);
    TcpClient(const std::string& host, unsigned short port, bool expectedSsl);
    ~TcpClient();
public:
    void Init();

    void SetExpectedSSL(bool expectedSSL){ this->expectedSsl = expectedSSL;}
    void SetTimeout(time_t sec);

    const std::string GetTlsVersion();
    const std::string GetCipher();
    const std::string GetSNI();

    void SetHost(const std::string& newHost){host = newHost;}
    void SetPort(unsigned short newPort){port = newPort;}

    int Connect();

    void Cleanup();

    int SendAll(std::vector<unsigned char>& buf);
    int SendAll(const std::string& toSend);

    int RecvAll(std::vector<unsigned char>& buf, size_t toRecv, size_t offset = 0);
    int RecvLine(std::vector<unsigned char>& buf);
    int PeekEndOfDelimiter(const std::vector<unsigned char>& delimiter, int size);

    void SetVerify(bool setVeriy);

    void SetMinVersion(int version);
    void SetMaxVersion(int version);
    int SetCipherSuiteList(const std::string& list);
    void DisableNagle();

    const std::string GetCiphers();

    bool IsConnected();
    void FastDisconnect();
    

};
