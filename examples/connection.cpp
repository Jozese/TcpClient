#include "../include/TcpClient/TcpClient.h"
#include <iomanip>
#include <openssl/prov_ssl.h>

/*
    Connects to example.com on port 443
    g++ connection.cpp -L../lib -lTcpClient -lssl -lcrypto

*/

int main() {

  TcpClient tcp("example.com", 443);
  tcp.Init();
  tcp.SetTimeout(10);

  if (tcp.Connect() == 0) {
    std::cout << "Connected!\n";
    std::cout << "TLS Cipher Used: " << tcp.GetCipher() << std::endl;
    std::cout << "TLS Version: " << tcp.GetTlsVersion() << std::endl;
    std::cout << "SNI: " << tcp.GetSNI() << std::endl;
    std::cout << "Verify: " << tcp.GetVerification() << std::endl;
    std::cout << "Key type: " << tcp.GetPubKey().first << std::endl;
    tcp.GetCertDigest();
  } else {
    std::cout << "Failed to connect!\n";
  }
}
