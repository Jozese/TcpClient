
#pragma once

#include <iostream>
#include <string>
#include <vector>
#include<string>
#include<chrono>
#include <cstring>
#include<unordered_map>
#include <locale>
#include <cstdlib>

#include <openssl/ssl.h>
#include <openssl/err.h>


#ifdef __linux__


#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

class TcpClient {

private:
    int cSocket = -1;
    sockaddr_in sAddr;

    addrinfo *dnsResult = nullptr, *iter = nullptr;

    std::string host;
    unsigned short port;

    SSL_CTX* sslCtx = nullptr;
    SSL* ssl = nullptr;

    int SSL_ERROR;

private:
    int ResolveDomainName();
    int SocketCreate();

public:
    TcpClient(const std::string& host, unsigned short port);
    ~TcpClient();

public:
    const std::string GetTlsVersion();
    const std::string GetCipher();
    const std::string GetSNI();

    int Connect();

    int SendAll(std::vector<unsigned char>& buf);
    int SendAll(const std::string& toSend);

    int Recv(std::vector<unsigned char>& buf, size_t toRecv);

};


#elif _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#include <ip2string.h>

class TcpClient
{
private:

    char ipv4[INET_ADDRSTRLEN];

    WSADATA wsaData;

    int cSocket = -1;
    sockaddr_in sAddr;

    addrinfo* dnsResult = nullptr, * iter = nullptr;

    std::string host;
    unsigned short port;

    SSL_CTX* sslCtx = nullptr;
    SSL* ssl = nullptr;

    int SSL_ERROR;

private:
    int ResolveDomainName();
    int SocketCreate();

public:
    TcpClient(const std::string& host, unsigned short port);

public:
    const std::string GetTlsVersion();
    const std::string GetCipher();
    const std::string GetSNI();

    int Connect();

    int SendAll(std::vector<unsigned char>& buf);
    int SendAll(const std::string& toSend);

    int Recv(std::vector<unsigned char>& buf, size_t toRecv);
};

#endif