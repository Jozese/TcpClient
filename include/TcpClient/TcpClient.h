
#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <locale>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#ifdef __linux__

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#elif _WIN32
#include <ip2string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
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

  SSL_CTX *sslCtx = nullptr;
  SSL *ssl = nullptr;
  X509 *cert = nullptr;

  bool isSsl = true;
  bool expectedSsl = true;
  bool pinnedPublicKey = false;

private:
  int ResolveDomainName();
  int SocketCreate();
  void Cleanup();

public:
  TcpClient();
  TcpClient(const std::string &host, unsigned short port);
  TcpClient(const std::string &host, unsigned short port, bool expectedSsl);
  ~TcpClient();

public:
  const std::string GetTlsVersion();
  const std::string GetCipher();
  const std::string GetSNI();
  const std::string GetCiphers();

public:
  void SetHost(const std::string &newHost) { host = newHost; }
  void SetPort(unsigned short newPort) { port = newPort; }

public:
  // TLS/SOCK SETTINGS
  void SetVerify(bool setVeriy);
  void SetMinVersion(int version);
  void SetMaxVersion(int version);
  void SetALPN(unsigned char *proto, size_t protoSize);
  void OverwriteSNI(const std::string &sni);
  int SetCipherSuiteList(const std::string &list);
  void DisableNagle();
  void SetExpectedSSL(bool expectedSSL) { this->expectedSsl = expectedSSL; }
  void SetTimeout(time_t sec);

public:
  // CERTIFICATE STUFF
  long GetVerification();
  X509 *GetCert();
  std::pair<int, std::vector<unsigned char>> GetPubKey();
  std::vector<unsigned char> GetCertDigest();

public:
  // READ/WRITE
  int SendAll(std::vector<unsigned char> &buf);
  int SendAll(const std::string &toSend);

  int Read(std::vector<unsigned char> &buf);
  int RecvAll(std::vector<unsigned char> &buf, size_t toRecv,
              size_t offset = 0);
  int PeekEndOfDelimiter(const std::vector<unsigned char> &delimiter, int size);

public:
  // CON RELATED
  void Init();
  int Connect();
  bool IsConnected();
  void FastDisconnect();
  bool UpgradeConnection();
};
