/*
*   @author Jozese
*   
*/

#pragma once

#include <iostream>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/err.h>


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
    //~TcpClient();

public:
    const int GetTlsVersion();
    const std::string GetCipher();

    int Connect();

    int SendAll(std::vector<unsigned char>& buf);
    int SendAll(const std::string& toSend);

    int Recv(std::vector<unsigned char>& buf, size_t toRecv);

};

