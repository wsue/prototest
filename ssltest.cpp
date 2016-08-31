#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <linux/tcp.h>

#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "ssltest.h"

#define PRNMSG(fmt,arg...)  printf("[%s:%d] " fmt,__func__,__LINE__,##arg)

static int socket_listen(int port)
{
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    int enable = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
        perror("setsockopt(SO_REUSEADDR) failed");

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        close(s);
        return -1;
    }

    if (listen(s, 10) < 0) {
        perror("Unable to listen");
        close(s);
        return -1;
    }

    return s;
}

static int socket_tcpnodelay(int fd)
{
    int enable = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void*)&enable, sizeof(enable)) ;
}

static int socket_connect(const char* addr, int port)
{
    int sockfd;
    struct sockaddr_in dest_addr;

    memset(&dest_addr,0,sizeof(dest_addr));


    /* ---------------------------------------------------------- *
     * create the basic TCP socket                                *
     * ---------------------------------------------------------- */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    dest_addr.sin_family=AF_INET;
    dest_addr.sin_port=htons(port);
    dest_addr.sin_addr.s_addr = inet_addr(addr);//*(long*)(host->h_addr);

    /* ---------------------------------------------------------- *
     * Try to make the host connect here                          *
     * ---------------------------------------------------------- */
    if ( connect(sockfd, (struct sockaddr *) &dest_addr,
                sizeof(dest_addr)) == -1 ) {
        PRNMSG( "Error: Cannot connect to host %s on port %d.\n",
                addr, port);
        close(sockfd);
        return -1;
    }

    socket_tcpnodelay(sockfd);
    return sockfd;
}

static void ssl_init()
{ 
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
}

static void ssl_cleanup()
{
    ERR_free_strings();
    EVP_cleanup();
}

static SSL_CTX *ssl_servctx_init(const char*certpem,const char* keypem)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, certpem, SSL_FILETYPE_PEM) < 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, keypem, SSL_FILETYPE_PEM) < 0 ) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

static SSL *ssl_servctx_accept(int sd,SSL_CTX *ctx)
{
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sd);

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }

    return ssl;
}

static SSL_CTX *ssl_clientctx_init()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    /* ---------------------------------------------------------- *
     * initialize SSL library and register algorithms             *
     * ---------------------------------------------------------- */
    if(SSL_library_init() < 0){
        PRNMSG("Could not initialize the OpenSSL library !\n");
        return NULL;
    }

    /* ---------------------------------------------------------- *
     * Set SSLv2 client hello, also announce SSLv3 and TLSv1      *
     * ---------------------------------------------------------- */
    method = SSLv23_client_method();

    /* ---------------------------------------------------------- *
     * Try to create a new SSL context                            *
     * ---------------------------------------------------------- */
    if ( (ctx = SSL_CTX_new(method)) == NULL){
        PRNMSG( "Unable to create a new SSL context structure.\n");
        return NULL;
    }
    /* ---------------------------------------------------------- *
     * Disabling SSLv2 will leave v3 and TSLv1 for negotiation    *
     * ---------------------------------------------------------- */
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

    return ctx;
}

static SSL *ssl_clientctx_connect(int sd,SSL_CTX *ctx)
{
    SSL *ssl;
    /* ---------------------------------------------------------- *
     * Create new SSL connection state object                     *
     * ---------------------------------------------------------- */
    ssl = SSL_new(ctx);

    /* ---------------------------------------------------------- *
     * Attach the SSL session to the socket descriptor            *
     * ---------------------------------------------------------- */
    SSL_set_fd(ssl, sd);

    /* ---------------------------------------------------------- *
     * Try to SSL-connect here, returns 1 for success             *
     * ---------------------------------------------------------- */
    if ( SSL_connect(ssl) != 1 ){
        PRNMSG("Error: Could not build a SSL session \n");
        SSL_free(ssl);
        return NULL;
    }

    return ssl;
#if 0
    X509                *cert = NULL;
    X509_NAME       *certname = NULL;
    /* ---------------------------------------------------------- *
     * Get the remote certificate into the X509 structure         *
     * ---------------------------------------------------------- */
    cert = SSL_get_peer_certificate(ssl);
    if (cert == NULL)
        BIO_printf(outbio, "Error: Could not get a certificate from: %s.\n", dest_url);
    else
        BIO_printf(outbio, "Retrieved the server's certificate from: %s.\n", dest_url);

    /* ---------------------------------------------------------- *
     * extract various certificate information                    *
     * -----------------------------------------------------------*/
    certname = X509_NAME_new();
    certname = X509_get_subject_name(cert);

    /* ---------------------------------------------------------- *
     * display the cert subject here                              *
     * -----------------------------------------------------------*/
    BIO_printf(outbio, "Displaying the certificate subject data:\n");
    X509_NAME_print_ex(outbio, certname, 0, 0);
    BIO_printf(outbio, "\n");

    /* ---------------------------------------------------------- *
     * Free the structures we don't need anymore                  *
     * -----------------------------------------------------------*/
    SSL_free(ssl);
    close(server);
    X509_free(cert);
    SSL_CTX_free(ctx);
    BIO_printf(outbio, "Finished SSL/TLS connection with server: %s.\n", dest_url);
#endif
}

SSLProtoClientTest::SSLProtoClientTest(SSL_CTX* ctx,const char* serv,int port){
    serv_   = serv;
    port_   = port;
    ctx_    = ctx;
}

SSLProtoClientTest::~SSLProtoClientTest(){
    Close();
    ssl_cleanup();
}


SSLProtoClientTest* SSLProtoClientTest::Create(const char* serv,int port){
    if( !serv || inet_addr(serv) == INADDR_ANY ){
        PRNMSG("invalid server address\n");
        return NULL;
    }

    SSL_CTX *ctx = ssl_clientctx_init();
    if( !ctx ){
        PRNMSG("init ssl fail, exit\n");
        return NULL;
    }

    return new SSLProtoClientTest(ctx,serv,port);
}

void SSLProtoClientTest::Close()
{
    if( ctx_ ){
        SSL_CTX*            ctx = ctx_;
        ctx_    = NULL;
        SSL_CTX_free(ctx);
    }
}

SSLStream* SSLProtoClientTest::CreateStream(){
    if( ctx_ ){
        int sd  = socket_connect(serv_.c_str(),port_);
        if( sd < 0 ){
            PRNMSG("connect to %s:%d fail, err:%d\n",serv_.c_str(),port_,errno);
            return NULL;
        }

        SSL * ssl = ssl_clientctx_connect(sd,ctx_);
        if( ssl ){
            return new SSLStream(sd,ssl);
        }
        PRNMSG("ssl connect fail\n");
        close(sd);
    }
    return NULL;
}

SSLProtoServTest::SSLProtoServTest(int ld,SSL_CTX* ctx,PROTOSERVER_TASK_ROUTINE acceptor)
{
    sd_         = ld;
    acceptor_   = acceptor;
    ctx_        = ctx;
}


SSLProtoServTest::~SSLProtoServTest()
{
    Close();
    ssl_cleanup();
}


SSLProtoServTest* SSLProtoServTest::Create( PROTOSERVER_TASK_ROUTINE acceptor,int port,const char* serv)
{
    ssl_init();
    int ld  = socket_listen(port);
    if( ld < 0 ){
        PRNMSG("bind to port %d fail\n",port);
        return NULL;
    }

    SSL_CTX *ctx = ssl_servctx_init(SSL_TEST_PEM_PUB,SSL_TEST_PEM_PRVI);
    if( ctx ){
        return new SSLProtoServTest(ld,ctx,acceptor);
    }

    PRNMSG("init ctx fail\n");

    close(ld);
    return NULL;
}

bool SSLProtoServTest::Run(bool fake)
{
    while( sd_ >= 0){
        sockaddr_storage    cli_addr;
        socklen_t clilen          = sizeof(cli_addr);
        int newsd = accept(sd_, (struct sockaddr *) &cli_addr, &clilen);
        if( newsd < 0 )
            continue;

	socket_tcpnodelay(newsd);
        SSL* ssl = ssl_servctx_accept(newsd,ctx_);
        if (ssl == NULL) {
            close(newsd);
            continue;
        }

        SSLStream *base = new SSLStream(newsd,ssl);
        if( !acceptor_(base) ){
            SSL_free(ssl);
            close(newsd);
        }
    }
    return true;
}

void SSLProtoServTest::Close()
{
    if( sd_ > 0){
        int         sd = sd_;
        SSL_CTX*    ctx = ctx_;
        ctx_    = NULL;
        sd_     = -1;
        close(sd);
        SSL_CTX_free(ctx);
    }
}

bool SSLStream::Read(std::string& out)
{
    char    buf[16384];
    if( !ssl_ )
        return false;

    int ret = SSL_read(ssl_,buf,sizeof(buf));
    if( ret > 0 ){
        out.assign(buf,ret);
        return true;
    }
    else{
        PRNMSG("read data fail,will close\n");
        //ERR_print_errors_fp(stderr);
        Close();
        return false;
    }
#if 0
    int ret = SSL_read(ssl_,buf,2);
    if( ret != 2 ){
        PRNMSG("read data fail,will close\n");
        //ERR_print_errors_fp(stderr);
        Close();
        return -1;
    }

    uint16_t *vsz   = (uint16_t *)buf;
    uint16_t len    = htons(*vsz);
    if( len > sizeof(buf)){
        PRNMSG("data size %d invalid,will close\n",len);
        Close();
        return -1;
    }

    int offset = 2;
    while( offset < len ){
        ret = SSL_read(ssl_,buf+offset,len - offset);
        if( ret > 0 ){
            offset  += ret;

            if( offset <= len ){
                continue;
            }
        }
        PRNMSG("read data fail,will close ,ret:%d hasread:%d expect:%d\n",ret,offset,len);
        ERR_print_errors_fp(stderr);
        Close();
        return -1;
    }

    out.assign(buf,len);
    return len;
#endif
}

#if 0
bool SSLStream::ReadN(std::string& out)
{
    char    buf[16384];
    if( !ssl_ )
	return false;

    int ret = SSL_read(ssl_,buf,2);
    if( ret != 2 ){
	PRNMSG("read data fail,will close\n");
	//ERR_print_errors_fp(stderr);
	Close();
	return false;
    }

    uint16_t *vsz   = (uint16_t *)buf;
    uint16_t len    = htons(*vsz);
    if( len > sizeof(buf)){
	PRNMSG("data size %d invalid,will close\n",len);
	Close();
	return false;
    }

    int offset = 2;
    while( offset < len ){
	ret = SSL_read(ssl_,buf+offset,len - offset);
	if( ret > 0 ){
	    offset  += ret;

	    if( offset <= len ){
		continue;
	    }
	}
	PRNMSG("read data fail,will close ,ret:%d hasread:%d expect:%d\n",ret,offset,len);
	ERR_print_errors_fp(stderr);
	Close();
	return false;
    }

    out.assign(buf,len);
    return true;
}
#endif

bool SSLStream::Write(const char* data,int len)
{
    if( !ssl_ )
        return false;

    uint16_t    size  = len;
    while( size > 0 ){
        int ret = SSL_write(ssl_,data,size);
        if( ret > 0 ){
            data += ret;
            size  -= ret;
            if( size >= 0 ){
                continue;
            }
        }

        PRNMSG("read data fail,will close ,ret:%d rest:%d total:%d\n",ret,size,len);
        ERR_print_errors_fp(stderr);
        Close();
        return false;
    }

    return true;
}
    
bool SSLStream::WriteN(const char* data,int len)
{
    assert( len == htons(*(uint16_t *)data));
    return Write(data,len);
}

void SSLStream::Close(bool wait)
{
    int         sd = sd_;
    SSL*    ssl = ssl_;
    ssl_    = NULL;
    sd_     = -1;
    close(sd);
    SSL_free(ssl);
}
