#include "../include/TcpClient/TcpClient.h"

TcpClient::TcpClient(){
    #ifdef _WIN32
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		WSACleanup(); 
	}
    #endif

    SSL_library_init();
    this->sslCtx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_mode(sslCtx, SSL_MODE_ENABLE_PARTIAL_WRITE);
    SSL_CTX_set_mode(sslCtx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_mode(sslCtx, SSL_MODE_AUTO_RETRY);
}

TcpClient::TcpClient(const std::string& host, unsigned short port):
host(host), port(port){

#ifdef _WIN32
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		WSACleanup(); 
	}
#endif

    SSL_library_init();
    this->sslCtx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_mode(sslCtx, SSL_MODE_ENABLE_PARTIAL_WRITE);
    SSL_CTX_set_mode(sslCtx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_mode(sslCtx, SSL_MODE_AUTO_RETRY);

}

TcpClient::TcpClient(const std::string& host, unsigned short port, bool expectedSsl):
host(host), port(port), expectedSsl(expectedSsl){

#ifdef _WIN32
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		WSACleanup(); 
	}
    
#endif

    SSL_library_init();
    this->sslCtx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_mode(sslCtx, SSL_MODE_ENABLE_PARTIAL_WRITE);
    SSL_CTX_set_mode(sslCtx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_mode(sslCtx, SSL_MODE_AUTO_RETRY);


}

void TcpClient::Init(){
    SocketCreate();
}

int TcpClient::Connect(){
    

    if(cSocket == -1)
        return 1;

    if(expectedSsl){
        if (SSL_set_fd(ssl, this->cSocket) != 1) {
            SSL_free(ssl);
            SSL_CTX_free(this->sslCtx);
            ssl = nullptr;
            sslCtx = nullptr;
            #ifdef _WIN32
                closesocket(cSocket);
            #elif __linux__
                close(cSocket);
            #endif            
                return 1;
        }

        if (SSL_set_tlsext_host_name(ssl, host.c_str()) != 1) {
            SSL_free(ssl);
            SSL_CTX_free(this->sslCtx);
            ssl = nullptr;
            sslCtx = nullptr;
            #ifdef _WIN32
                closesocket(cSocket);
            #elif __linux__
                close(cSocket);
            #endif           
            return 1;
        }
    }
    
#ifdef __linux__
    if(connect(this->cSocket, iter->ai_addr, iter->ai_addrlen) == -1){
        SSL_free(ssl);
        SSL_CTX_free(this->sslCtx);
        ssl = nullptr;
        sslCtx = nullptr;
        close(cSocket);
        return 1;
    }
    #elif _WIN32
    if (connect(cSocket, (SOCKADDR*)&sAddr, sizeof(sAddr)) == SOCKET_ERROR) {
		closesocket(cSocket);
		WSACleanup();
        ssl = nullptr;
        sslCtx = nullptr;
		return 1;
	}
#endif


    if(expectedSsl){
        if (SSL_connect(ssl) != 1) {
            isSsl = false;
        } 
    }else{
        isSsl = false;
    }

    return 0;
}

void TcpClient::Cleanup(){
    if (cSocket != -1) {
        #ifdef _WIN32
            closesocket(cSocket);
        #elif __linux__
            close(cSocket);
        #endif
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

TcpClient::~TcpClient(){
    Cleanup();
}


#ifdef __linux__

int TcpClient::ResolveDomainName(){
    addrinfo hints;

    memset(&hints, 0, sizeof hints);

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    return getaddrinfo(this->host.c_str(), std::to_string(port).c_str(), &hints, &dnsResult);
}

int TcpClient::SocketCreate(){
    
    ssl = SSL_new(this->sslCtx);

    if(!dnsResult){
        int status = ResolveDomainName();
        if(status != 0){
            freeaddrinfo(dnsResult);
            return 1;
        }
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


#elif _WIN32

int TcpClient::ResolveDomainName()
{
	int resolve = getaddrinfo(this->host.c_str(), 0, nullptr, &dnsResult);
	if (resolve != 0) {
		return -1;
	}
	return resolve;
}

int TcpClient::SocketCreate()
{

    ssl = SSL_new(this->sslCtx);

	sAddr.sin_family = AF_INET;
	sAddr.sin_port = htons(port);

	addrinfo hints;
	hints.ai_family = AF_INET;

	if (ResolveDomainName() == -1) {
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
    std::string sni = this->host;

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
            nSent = send(this->cSocket, toSend.data() + totalSent, leftToSend, 0);        
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
            nSent = send(this->cSocket, reinterpret_cast<char*>(buf.data() + totalSent), leftToSend, 0);
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
            nRecv = recv(this->cSocket, reinterpret_cast<char*>(buf.data() + offset + total), toRecv - total, MSG_WAITALL);
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


//Kinda useless to iterate since we will just get the same data over and over.
int TcpClient::PeekEndOfDelimiter(const std::vector<unsigned char>& delimiter, int max_size) {
    std::vector<unsigned char> peek_buf(max_size);
    int total_bytes_peeked = 0;
    int retry_count = 0;

    while (total_bytes_peeked < max_size) {
        int bytes_peeked;
        if (isSsl) {
            bytes_peeked = SSL_peek(ssl, reinterpret_cast<char*>(peek_buf.data() + total_bytes_peeked), max_size - total_bytes_peeked);
            if (bytes_peeked <= 0) {
                return -1;
            }
        } else {
            bytes_peeked = recv(cSocket, reinterpret_cast<char*>(peek_buf.data() + total_bytes_peeked), 
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

    }

    return -1;
}

int TcpClient::Read(std::vector<unsigned char>& buf){
    unsigned char tmp[1024];
    int bytes_read = -1;

    if(isSsl){
        bytes_read = SSL_read(ssl, tmp, sizeof(tmp));
        if (bytes_read <= 0)
            return -1;
    }
    else{
        bytes_read = recv(cSocket, reinterpret_cast<char*>(tmp), sizeof(tmp), 0);
        if (bytes_read <= 0)
            return -1;
    }
    buf.insert(buf.end(), tmp, tmp + bytes_read);
    return bytes_read;
}



// Lots of checks to see if we are connected and also connected to the same host
bool TcpClient::IsConnected() {
    if (cSocket < 0) {
        return false;
    }

    int error = 0;
    socklen_t len = sizeof(error);
    #ifdef __linux__
    int err = getsockopt(cSocket, SOL_SOCKET, SO_ERROR, &error, &len);
    #elif _WIN32
    int err = getsockopt(cSocket, SOL_SOCKET, SO_ERROR, (char*)&error, &len);
    #endif
    if (err < 0 || error != 0)
        return false;

    if (isSsl) {
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
    FD_SET(cSocket, &read_fds);
    FD_SET(cSocket, &write_fds);
    FD_SET(cSocket, &except_fds);
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    int select_result = select(cSocket + 1, &read_fds, &write_fds, &except_fds, &timeout);
    if (select_result < 0 || FD_ISSET(cSocket, &except_fds)) {
        return false;
    }

    struct sockaddr_in peer_addr;
    socklen_t peer_addr_len = sizeof(peer_addr);
    if (getpeername(cSocket, (struct sockaddr*)&peer_addr, &peer_addr_len) != 0) {
        return false;  
    }

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;  
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0) {
        return false;  
    }

    bool ip_match = false;
    for (struct addrinfo* addr = res; addr != nullptr; addr = addr->ai_next) {
        struct sockaddr_in* resolved_addr = (struct sockaddr_in*)addr->ai_addr;
        if (peer_addr.sin_addr.s_addr == resolved_addr->sin_addr.s_addr) {
            // If new host, we save the new dns result so we dont have to resolve again on connection
            ip_match = true;
            dnsResult = res;
            break;
        }
    }

    return ip_match && (FD_ISSET(cSocket, &read_fds) || FD_ISSET(cSocket, &write_fds));
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
    if(sslCtx){
        int max_version = SSL_CTX_get_max_proto_version(sslCtx);
        if (max_version == TLS1_3_VERSION) {
            return SSL_CTX_set_ciphersuites(sslCtx, list.c_str());
        }
        else{
            return SSL_CTX_set_cipher_list(sslCtx, list.c_str());
        }
    }
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

void TcpClient::SetVerify(bool setVeriy){
    if(sslCtx){
        if(!setVeriy)
            SSL_CTX_set_verify(sslCtx, SSL_VERIFY_NONE, nullptr);

    }
}