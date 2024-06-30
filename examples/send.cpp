#include "../include/TcpClient/TcpClient.h"

/*
    Connects to httpbin.org on port 443 and sends/recieve an http request/response
    g++ send.cpp -L../lib -lTcpClient -lssl -lcrypto

*/

int main(){
    
    TcpClient tcp("httpbin.org", 443);

    if (tcp.Connect() == 0)
    {
        std::cout << "Connected!\n";
        std::cout << "TLS Cipher Used: " << tcp.GetCipher() << std::endl;
        std::cout << "TLS Version: " << tcp.GetTlsVersion();
        std::cout << "SNI: " << tcp.GetSNI();
    }

    const std::string httpReq = "GET /get HTTP/1.1\r\nConnection: close\r\nHost: httpbin.org\r\nAccept: application/json\r\nUser-agent: JozeseTcpClient\r\n\r\n";

    std::vector<unsigned char> recvBuffer(1024);

    int sent = tcp.SendAll(httpReq);

    //Reading arbitrary 1024 bytes obviously you should not read a generic http response this way.
    int recv = tcp.Recv(recvBuffer,1024);

    std::cout << "\n\n" <<"Sent " << sent << " bytes\n";
    std::cout << "Recvd " << recv << " bytes\n";

    std::cout << "\n\n" << recvBuffer.data() + '\0'; 

}