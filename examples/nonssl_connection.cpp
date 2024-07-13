#include "../include/TcpClient/TcpClient.h"

/*
    Connects to info.cern.ch on port 80
    g++ nonssl_connection.cpp -L../lib -lTcpClient -lssl -lcrypto

*/

int main(){
    
    TcpClient tcp("info.cern.ch", 80, false);

    if (tcp.Connect() == 0)
    {
        std::cout << "Connected!\n";
        std::cout << "TLS Cipher Used: " << tcp.GetCipher() << std::endl;
        std::cout << "TLS Version: " << tcp.GetTlsVersion() << std::endl;   
        std::cout << "SNI: " << tcp.GetSNI();
    }
    else{
        std::cout << "Failed to connect!\n"; 
    }

}