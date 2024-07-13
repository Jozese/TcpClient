#include "../include/TcpClient/TcpClient.h"

#ifdef __linux__

TcpClient::TcpClient(const std::string& host, unsigned short port):
host(host), port(port){
    SSL_library_init();
    this->sslCtx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_mode(sslCtx, SSL_MODE_ENABLE_PARTIAL_WRITE);
    SSL_CTX_set_mode(sslCtx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_mode(sslCtx, SSL_MODE_AUTO_RETRY);
}

TcpClient::TcpClient(const std::string& host, unsigned short port, bool expectedSsl):
host(host), port(port), expectedSsl(expectedSsl){
    SSL_library_init();
    this->sslCtx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_mode(sslCtx, SSL_MODE_ENABLE_PARTIAL_WRITE);
    SSL_CTX_set_mode(sslCtx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_mode(sslCtx, SSL_MODE_AUTO_RETRY);
}

int TcpClient::ResolveDomainName(){
    addrinfo hints;

    memset(&hints, 0, sizeof hints);

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    return getaddrinfo(this->host.c_str(), std::to_string(port).c_str(), &hints, &dnsResult);
}

int TcpClient::SocketCreate(){
    
    ssl = SSL_new(this->sslCtx);
  

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
        return 1;
    }
    
    if(expectedSsl){
        if (SSL_set_fd(ssl, this->cSocket) != 1) {
            SSL_free(ssl);
            SSL_CTX_free(this->sslCtx);
            ssl = nullptr;
            sslCtx = nullptr;
            close(this->cSocket);
            return 1;
        }

        if (SSL_set_tlsext_host_name(ssl, host.c_str()) != 1) {
            SSL_free(ssl);
            SSL_CTX_free(this->sslCtx);
            ssl = nullptr;
            sslCtx = nullptr;
            close(this->cSocket);
            return 1;
        }
    }
    

    if(connect(this->cSocket, iter->ai_addr, iter->ai_addrlen) == -1){
        SSL_free(ssl);
        SSL_CTX_free(this->sslCtx);
        ssl = nullptr;
        sslCtx = nullptr;
        close(this->cSocket);
        return 1;
    }

    if(expectedSsl){
        if (SSL_connect(ssl) != 1) {
            isSsl = false;
        } 
    }

    return 0;
}

void TcpClient::Cleanup(){
    if (cSocket != -1) {
        close(cSocket);
    }
    if(isSsl){
        if (ssl != nullptr) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        if (sslCtx != nullptr) {
            SSL_CTX_free(sslCtx);
        }
    }
    if (dnsResult != nullptr) {
        freeaddrinfo(dnsResult);
    }
}

TcpClient::~TcpClient(){
    Cleanup();
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
        ssl = nullptr;
        sslCtx = nullptr;
		return 1;
	}

	if (connect(cSocket, (SOCKADDR*)&sAddr, sizeof(sAddr)) == SOCKET_ERROR) {
		std::cerr << "Failed to establish TCP handshake." << WSAGetLastError() << std::endl;
		closesocket(cSocket);
		WSACleanup();
        ssl = nullptr;
        sslCtx = nullptr;
		return 1;
	}

	SSL_set_fd(ssl, cSocket);

    if (SSL_set_tlsext_host_name(ssl, host.c_str()) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(this->sslCtx);
        closesocket(this->cSocket);
        ssl = nullptr;
        sslCtx = nullptr;
        return 1;
    }

	if (SSL_connect(ssl) != 1) {
		std::cerr << "Failed to establish SSL/TLS handshake." << std::endl;
		closesocket(cSocket);
		SSL_shutdown(ssl);
		SSL_free(ssl);
		WSACleanup();
        ssl = nullptr;
        sslCtx = nullptr;
		return 1;
	}

	return 0;
}


#endif

const std::string TcpClient::GetTlsVersion() {
    if(isSsl && ssl)
        return SSL_get_version(this->ssl); 
    return "";
}

const std::string TcpClient::GetCipher() {
    if(isSsl && ssl)
        return SSL_get_cipher(this->ssl);
    return "";
}

const std::string TcpClient::GetSNI() {
    std::string sni = "";

    if(isSsl && ssl)
        sni = SSL_get_servername(this->ssl,TLSEXT_NAMETYPE_host_name);
    return sni;
}

int TcpClient::SendAll(const std::string& toSend){
    int totalSent = 0;
    int leftToSend = toSend.size();

    int nSent;
    while (totalSent < toSend.size())
    {
        if (isSsl) {
            nSent = SSL_write(this->ssl, toSend.data() + totalSent, leftToSend);
        } 
        else {
            nSent = send(this->cSocket, toSend.data() + totalSent, leftToSend, MSG_NOSIGNAL);        
        }

        if(nSent <= 0);
            break;

        totalSent += nSent;
        leftToSend -= leftToSend;
    }
    return nSent;
}


int TcpClient::SendAll(std::vector<unsigned char>& buf) {
    
    int totalSent = 0;
    int leftToSend = buf.size();
    int nSent;

    while (totalSent < buf.size()) {
        if (isSsl) {
            nSent = SSL_write(this->ssl, buf.data() + totalSent, leftToSend);
        } else {
            nSent = send(this->cSocket, buf.data() + totalSent, leftToSend, 0);
        }

        if (leftToSend == 0) {
            break;
        }

        totalSent += nSent;
        leftToSend -= nSent;
        
    }
    return totalSent;
}

    
int TcpClient::RecvAll(std::vector<unsigned char>& buf, size_t toRecv, size_t offset) {
    buf.resize(offset + toRecv);
    int total = 0;
    do {
        int nRecv;
        if (isSsl) {
            nRecv = SSL_read(ssl, buf.data() + offset + total, toRecv - total);
            if (nRecv <= 0) {
                break;
            }
        } else {
            nRecv = recv(this->cSocket, buf.data() + offset + total, toRecv - total, MSG_WAITALL);
            if (nRecv <= 0) {
                break;
            }
        }
        total += nRecv;
    } while (total < toRecv);

    if (total < toRecv) {
        buf.resize(offset + total);
    }
    return total;
}



int TcpClient::PeekEndOfDelimiter(const std::vector<unsigned char>& delimiter, int max_size) {
    std::vector<unsigned char> peek_buf(max_size);
    int total_bytes_peeked = 0;
    int retry_count = 0;
    const int max_retries = 5;

    while (total_bytes_peeked < max_size) {
        int bytes_peeked;
        if (isSsl) {
            bytes_peeked = SSL_peek(ssl, peek_buf.data() + total_bytes_peeked, max_size - total_bytes_peeked);
            if (bytes_peeked <= 0) {
                return -1;
            }
        } else {
            bytes_peeked = recv(this->cSocket, peek_buf.data() + total_bytes_peeked, 
                                max_size - total_bytes_peeked, MSG_PEEK);
            if (bytes_peeked == -1) {
                return -1;
            }
        }

        total_bytes_peeked += bytes_peeked;
        
        auto found = std::search(peek_buf.begin(), peek_buf.begin() + total_bytes_peeked, 
                                 delimiter.begin(), delimiter.end());
        if (found != peek_buf.begin() + total_bytes_peeked) {
            return found - peek_buf.begin() + delimiter.size();
        }

        retry_count = 0;
    }

    return -1;
}

bool TcpClient::IsConnected() {

    int sockfd = cSocket;
    if (sockfd < 0) {
        return false;
    }

    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        return false;
    }
    if (error != 0) {
        return false;
    }

    if(isSsl){
        if (SSL_get_shutdown(ssl) & (SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN)) {
            return false;
        }

        if (SSL_pending(ssl) > 0) {
            return true;
    }
    }

    fd_set read_fds, write_fds, except_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    FD_ZERO(&except_fds);
    FD_SET(sockfd, &read_fds);
    FD_SET(sockfd, &write_fds);
    FD_SET(sockfd, &except_fds);

    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;

    int select_result = select(sockfd + 1, &read_fds, &write_fds, &except_fds, &timeout);

    if (select_result < 0) {
        return false;
    }

    if (FD_ISSET(sockfd, &except_fds)) {
        return false;
    }

    return FD_ISSET(sockfd, &read_fds) || FD_ISSET(sockfd, &write_fds);
}

void TcpClient::FastDisconnect(){
    if(ssl && isSsl){
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ssl = nullptr;
    }

    if (dnsResult != nullptr) {
        freeaddrinfo(dnsResult);
        dnsResult = nullptr;
    }

    if(cSocket != -1){
    #ifdef __linux__
        close(this->cSocket);
        cSocket = -1;
    #elif _WIN32
        closesocket(this->cSocket);
        cSocket = -1;
    #endif
    }
}

void TcpClient::SetTimeout(time_t sec){
        #ifdef __linux__
            struct timeval tv;
            tv.tv_sec = sec; 
            tv.tv_usec = 0;
            setsockopt(cSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
        #elif _WIN32
            DWORD millisec = static_cast<DWORD>(sec * 1000);
            setsockopt(cSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&millisec, sizeof(millisec));
        #endif

}

void TcpClient::DisableNagle(){
    int flag = 1;
    setsockopt(cSocket, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
}

void TcpClient::SetMaxVersion(int version){
    if(sslCtx)
        SSL_CTX_set_max_proto_version(sslCtx,version);
}

void TcpClient::SetMinVersion(int version){
    if(sslCtx)
        SSL_CTX_set_min_proto_version(sslCtx,version);
}

int TcpClient::SetCipherSuiteList(const std::string& list){
    if(sslCtx)
        return SSL_CTX_set_cipher_list(sslCtx,list.c_str());
    return 0;
}

const std::string TcpClient::GetCiphers(){
    std::stringstream ss;
    if(sslCtx){
        auto ciphers = SSL_CTX_get_ciphers(sslCtx);

        for(int i = 0; i < sk_SSL_CIPHER_num(ciphers); i++){
            const SSL_CIPHER* cipher = sk_SSL_CIPHER_value(ciphers, i);
            const char* cipherName = SSL_CIPHER_get_name(cipher);
            ss << cipherName << '\n';
        }
    }
    return ss.str();
}

void TcpClient::SetVerifyFalse(){
    if(sslCtx)
        SSL_CTX_set_verify(sslCtx, SSL_VERIFY_NONE, nullptr);
}