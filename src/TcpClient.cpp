#include "../include/TcpClient/TcpClient.h"

#ifdef __linux__

TcpClient::TcpClient(const std::string& host, unsigned short port):
host(host), port(port){

    SSL_library_init();
    this->sslCtx = SSL_CTX_new(TLS_client_method());
    ssl = SSL_new(this->sslCtx);

    SSL_CTX_set_verify(sslCtx, SSL_VERIFY_NONE, nullptr);

}

int TcpClient::ResolveDomainName(){
    addrinfo hints;

    memset(&hints, 0, sizeof hints);

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    return getaddrinfo(this->host.c_str(), std::to_string(port).c_str(), &hints, &dnsResult);
}

int TcpClient::SocketCreate(){

    int status = ResolveDomainName();
    if(status != 0){
        freeaddrinfo(dnsResult);
        return 1;
    }
    
    for(iter = dnsResult; iter != nullptr; iter = iter->ai_next){
        this->cSocket = socket(iter->ai_family, iter->ai_socktype, iter->ai_protocol);

        if(this->cSocket != -1)
            break;
    }
    if(this->cSocket == -1)
        return 1;
    return 0;
}

int TcpClient::Connect(){
    
    if(SocketCreate() != 0){
        
        close(this->cSocket);
        return 1;
    }

    if (SSL_set_fd(ssl, this->cSocket) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(this->sslCtx);
        close(this->cSocket);
        return 1;
    }

    if (SSL_set_tlsext_host_name(ssl, host.c_str()) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(this->sslCtx);
        close(this->cSocket);
        return 1;
    }

    if(connect(this->cSocket, iter->ai_addr, iter->ai_addrlen) == -1){
        close(this->cSocket);
        return 1;
    }

    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(this->sslCtx);
        close(this->cSocket);
        return 1;
    }

    // NON BLOCKING FLAG

    /*
    int flags = fcntl(cSocket, F_GETFL, 0);
    if (flags == -1) {
        return -1; 
    }

    flags |= O_NONBLOCK;
    if (fcntl(cSocket, F_SETFL, flags) == -1) {
        return -1; 
    }    
    */
    return 0;
}


int TcpClient::SendAll(std::vector<unsigned char>& buf) {
    int totalSent = 0;
    int leftToSend = buf.size();
    int nSent;

    while (totalSent < buf.size()) {
        nSent = SSL_write(this->ssl, buf.data() + totalSent, leftToSend);

        if (nSent <= 0) {
            int error = SSL_get_error(ssl, nSent);
            std::cout << "Error while sending: " << error << std::endl;
            break;
        }

        totalSent += nSent;
        leftToSend -= nSent;

        if (leftToSend == 0) {
            break;
        }
    }

    return totalSent;
}

int TcpClient::SendAll(const std::string& toSend){
    int totalSent = 0;
    int leftToSend = toSend.size();

    int nSent;
    while (totalSent < toSend.size())
    {
        nSent = SSL_write(this->ssl, toSend.data() + totalSent, leftToSend);

        if(nSent <= 0);
            break;
        totalSent += nSent;
        leftToSend -= leftToSend;
    }
    return nSent;
}


int TcpClient::Recv(std::vector<unsigned char>& buf, size_t toRecv){

    int total = 0;
    do{
        int nRecv = SSL_read(ssl, buf.data() + total, toRecv - total);
        if(nRecv <= 0)
            break;
        total += nRecv;

    }while (total < toRecv);
    
    return total;
}


TcpClient::~TcpClient(){
    if (cSocket != -1) {
        close(cSocket);
    }

    if (ssl != nullptr) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (sslCtx != nullptr) {
        SSL_CTX_free(sslCtx);
    }

    if (dnsResult != nullptr) {
        freeaddrinfo(dnsResult);
    }
}

#elif _WIN32

int TcpClient::ResolveDomainName()
{
	int resolve = getaddrinfo(this->host.c_str(), 0, nullptr, &dnsResult);
	if (resolve != 0) {
		std::cout << "Error while resolving hostname" << std::endl;
		return -1;
	}
	return resolve;
}

int TcpClient::SocketCreate()
{
	sAddr.sin_family = AF_INET;
	sAddr.sin_port = htons(port);

	addrinfo hints;
	hints.ai_family = AF_INET;

	if (ResolveDomainName() == -1) {
		std::cout << "getaddrinfo falied" << std::endl;
		return -1;
	}

	sockaddr_in* ipv4 = nullptr;
	for (addrinfo* result = dnsResult; result != nullptr; result = result->ai_next) {
		cSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
		if (this->cSocket == -1) {
			continue;
		}

		ipv4 = (sockaddr_in*)(result->ai_addr);
		inet_ntop(AF_INET, &(ipv4->sin_addr), this->ipv4, sizeof(this->ipv4));
	}

	if (ipv4 != nullptr) {
		sAddr.sin_addr = ipv4->sin_addr;
	}
	

	if (this->cSocket == -1)
		return 1;
	
	return 0;
}

TcpClient::TcpClient(const std::string& host, unsigned short port):
	host(host), port(port)
{

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		std::cerr << "Winsock dll was not found! " << WSAGetLastError() << std::endl;
		WSACleanup(); 
	}

	SSL_library_init();
	this->sslCtx = SSL_CTX_new(TLS_client_method());
	ssl = SSL_new(this->sslCtx);

}

int TcpClient::Connect()
{
	if (SocketCreate() != 0) {
		std::cout << "Failed to create socket " << WSAGetLastError() << std::endl;
		closesocket(cSocket);
		WSACleanup();
		return 1;
	}

	if (connect(cSocket, (SOCKADDR*)&sAddr, sizeof(sAddr)) == SOCKET_ERROR) {
		std::cerr << "Failed to establish TCP handshake." << WSAGetLastError() << std::endl;
		closesocket(cSocket);
		WSACleanup();
		return 1;
	}

	SSL_set_fd(ssl, cSocket);

    if (SSL_set_tlsext_host_name(ssl, host.c_str()) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(this->sslCtx);
        close(this->cSocket);
        return 1;
    }

	if (SSL_connect(ssl) != 1) {
		std::cerr << "Failed to establish SSL/TLS handshake." << std::endl;
		closesocket(cSocket);
		SSL_shutdown(ssl);
		SSL_free(ssl);
		WSACleanup();
		return 1;
	}

	return 0;
}

int TcpClient::SendAll(std::vector<unsigned char>& buf)
{
	int totalSent = 0;
	int leftToSend = buf.size();
	int nSent;

	while (totalSent < buf.size()) {
		nSent = SSL_write(this->ssl, buf.data() + totalSent, leftToSend);

		if (nSent <= 0) {
			int error = SSL_get_error(ssl, nSent);
			std::cout << "Error while sending: " << error << std::endl;
			break;
		}

		totalSent += nSent;
		leftToSend -= nSent;

		if (leftToSend == 0) {
			break;
		}
	}

	return totalSent;
}

int TcpClient::SendAll(const std::string& toSend)
{
	int totalSent = 0;
	int leftToSend = toSend.size();

	int nSent;
	while (totalSent < toSend.size())
	{
		nSent = SSL_write(this->ssl, toSend.data() + totalSent, leftToSend);

		if (nSent <= 0);
		break;
		totalSent += nSent;
		leftToSend -= leftToSend;
	}
	return nSent;
}

int TcpClient::Recv(std::vector<unsigned char>& buf, size_t toRecv)
{
	int total = 0;
	do {
		int nRecv = SSL_read(ssl, buf.data() + total, toRecv - total);
		if (nRecv <= 0)
			break;
		total += nRecv;

	} while (total < toRecv);

	return total;
}

#endif

const std::string TcpClient::GetTlsVersion() {
    return SSL_get_version(this->ssl); 
}

const std::string TcpClient::GetCipher() {
    return SSL_get_cipher(this->ssl);
}

const std::string TcpClient::GetSNI() {
    const char* sni = SSL_get_servername(this->ssl,TLSEXT_NAMETYPE_host_name);

    if(sni)
        return std::string(sni);

    return "";

}

