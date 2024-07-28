#include "../include/TcpClient/TcpClient.h"

/*
    Connects to example.com on port 443
    g++ connection.cpp -L../lib -lTcpClient -lssl -lcrypto

*/

int main(){
    
    TcpClient tcp("www.google.com", 443);
    tcp.Init();

    if (tcp.Connect() == 0)
    {
        std::cout << "Connected!\n";
        std::cout << "TLS Cipher Used: " << tcp.GetCipher() << std::endl;
        std::cout << "TLS Version: " << tcp.GetTlsVersion() << std::endl;   
        std::cout << "SNI: " << tcp.GetSNI() << std::endl;
        std::cout << "Verify: " << tcp.GetVerification() << std::endl;
        
    }
    else{
        std::cout << "Failed to connect!\n"; 
    }

}