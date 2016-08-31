#ifndef SSLPROTO_TEST_H_
#define SSLPROTO_TEST_H_

#include <string>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

// openssl req -x509 -nodes -newkey rsa:2048 -keyout key.pem -out cert.pem -days  300
#define SSL_TEST_PEM_PUB            "cert.pem"
#define SSL_TEST_PEM_PRVI           "key.pem"



#define WRAP_SYSAPI(ret,func)           do{ \
    ret = func;                             \
}while( ret == -1 && (errno == EAGAIN || errno == EINTR))


class SSLStream{
    int         sd_;
    SSL*        ssl_;

    std::string		cache_;

    bool ReadFromCache(std::string& out){
	if( !cache_.empty() ){
	    const char* pbuf = cache_.data();
	    const uint16_t *psz = (const uint16_t *)pbuf;
	    int readsz	= htons(*psz);
	    int cachesz	= cache_.size();
	    if( readsz <= cachesz ){
		out.swap(cache_);
		if( readsz != cachesz ){
		    cache_	= out.substr(readsz,cachesz - readsz);
		    out.resize(readsz);
		}

		return true;
	    }
	}

	return false;
    }

    public:
    SSLStream(int sd,SSL* ssl){
	sd_     = sd;
	ssl_    = ssl;
    }
    ~SSLStream(){
	Close();
    }

    uint32_t id(){   return (uint32_t) sd_; }
    bool IsConnected(){ return sd_ >= 0 && ssl_ != NULL ; }
    bool Read(std::string& out);
    bool Write(const char* data,int len);
    bool ReadN(std::string& out) {
	out.clear();

	while( !ReadFromCache(out) ){
	    std::string	tmp;
	    if( Read(tmp) ){
		cache_.append(tmp);
	    }
	}

	return true;
    }
    bool WriteN(const char* data,int len);
    void Close(bool wait = false);
};

class SSLProtoClientTest{
    std::string         serv_;
    int                 port_;
    SSL_CTX*            ctx_;

    SSLProtoClientTest(SSL_CTX* ctx,const char* serv,int port);

    public:
    ~SSLProtoClientTest();

    static SSLProtoClientTest* Create(const char* serv,int port);
    bool Connect(){ return ctx_ != NULL;}
    bool Run(bool fake){ 
        return true;
    }
    void Close();
    SSLStream* CreateStream();
};

typedef bool (*PROTOSERVER_TASK_ROUTINE)(SSLStream* stream);

class SSLProtoServTest{
    int                     sd_;
    PROTOSERVER_TASK_ROUTINE acceptor_;
    SSL_CTX*                ctx_;

    SSLProtoServTest(int ld,SSL_CTX* ctx,PROTOSERVER_TASK_ROUTINE acceptor);

    public:
    ~SSLProtoServTest();

    static SSLProtoServTest* Create(PROTOSERVER_TASK_ROUTINE acceptor,int port,const char* serv);
    bool Run(bool fake);
    void Close();
};

#endif
