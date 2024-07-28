#include "../include/TcpClient/TcpClient.h"
#include <iomanip>

/*
    Connects to example.com on port 443
    g++ connection.cpp -L../lib -lTcpClient -lssl -lcrypto

*/

int main(){
    
    TcpClient tcp("example.com", 443);
    tcp.Init();
    tcp.SetVerify(false);

    if (tcp.Connect() == 0)
    {
        std::cout << "Connected!\n";
        std::cout << "TLS Cipher Used: " << tcp.GetCipher() << std::endl;
        std::cout << "TLS Version: " << tcp.GetTlsVersion() << std::endl;   
        std::cout << "SNI: " << tcp.GetSNI() << std::endl;
        std::cout << "Verify: " << tcp.GetVerification() << std::endl;
        std::cout << "Key type: " << tcp.GetPubKey().first << std::endl;
        for(const auto& i : tcp.GetPubKey().second)
            std::cout << std::hex << std::setw(2) << std::setfill('0') <<(int)i << std::dec;

    }
    else{
        std::cout << "Failed to connect!\n"; 
    }

}