#include "../include/TcpClient/TcpClient.h"

/*
    Connects to httpbin.org on port 443 and sends/recieve an http request/response
    g++ send.cpp -L../lib -lTcpClient -lssl -lcrypto

*/

int main(){
    
    TcpClient tcp("127.0.0.1", 80);

    if (tcp.Connect() == 0)
    {
        std::cout << "Connected!\n";
        std::cout << "TLS Cipher Used: " << tcp.GetCipher() << std::endl;
        std::cout << "TLS Version: " << tcp.GetTlsVersion() << std::endl;
        std::cout << "SNI: " << tcp.GetSNI();
    }

    const std::string httpReq = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Close\r\n\r\n";

    std::vector<unsigned char> recvBuffer;
    auto httpReqData = std::vector<unsigned char>(httpReq.begin(), httpReq.end());

    std::cout << httpReq.size() << std::endl;
    int sent = tcp.SendAll(httpReq);

    //Reading arbitrary 1024 bytes
    int recv = tcp.RecvAll(recvBuffer,1024);

    std::cout << "\n\n" <<"Sent " << sent << " bytes\n";
    std::cout << "Recvd " << recv << " bytes\n";
    std::cout << "\n\n" << recvBuffer.data(); 

}