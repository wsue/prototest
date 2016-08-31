#ifndef TEST_HELPER_H_
#define TEST_HELPER_H_

#include <string>
#include <sys/timerfd.h>
#include <pthread.h>

#ifndef SSLPROTOTEST
#include "quicproto/quicbase.h"
#include "quicproto/quic_client_connect.h"
#include "quicproto/quic_server_connect.h"

using namespace net;
typedef class QuicClientConnect	ProtoClient;
typedef class QuicServer	ProtoServer;
typedef QuicStreamVisitorBase  	ProtoStream;
#else
#include "ssltest.h"

typedef class SSLProtoClientTest	ProtoClient;
typedef class SSLProtoServTest	ProtoServer;
typedef class SSLStream		ProtoStream;
#endif



#define TESTAPP_SHOW_WARNNING(fmt,arg...)  printf("[%s:%d] " fmt,__func__,__LINE__,##arg)
#define TESTAPP_SHOW_INFO(fmt,arg...)  printf("[%s:%d] " fmt,__func__,__LINE__,##arg)
#define TESTAPP_SHOW_ERROR(fmt,arg...)  printf("[%s:%d] " fmt,__func__,__LINE__,##arg)

#define PKGSIZE_MAX         32768
#define JOBNUM_MAX          256
#define SERVER_PORT         443
#define SERVER_FLOOD_PORT   444

#define DEFAULT_PKG_SIZE    1200

#define MONITOR_DEFAULT_INTERVAL	10	// sec

struct StreamStat{
    uint32_t    id;
    ProtoStream *visitor;

    bool        tracksnd;

    uint32_t    bytes;
    uint32_t    bytes_start;
    uint32_t    pkts;
    uint32_t    pkts_start;

    void Inc(uint32_t bytenum){
        pkts    ++;
        bytes   += bytenum;
    }

    void Sync(){
        bytes_start = bytes;
        pkts_start  = pkts;
    }
};

class MonitorCtl{
    StreamStat  streams_[JOBNUM_MAX];
    volatile int num_;
    timespec    last_;

    pthread_t	 thrid_;
    volatile int timer_;
   
    MonitorCtl(){
        memset(streams_,0,sizeof(streams_));
        num_        = 0;
            
	thrid_		= 0;
	WRAP_SYSAPI(timer_ , timerfd_create(CLOCK_MONOTONIC,TFD_CLOEXEC|TFD_NONBLOCK));
    }

    bool SetInterval(int interval_sec);
    bool Wait(){
	int64_t v;
	int ret;
	WRAP_SYSAPI(ret , read(timer_,&v,sizeof(int64_t)));
	return timer_ != -1 ? true : false;
    }

    void DoRun();
    static void Task(MonitorCtl* ctl);
    public:
    static int Time2Str(char *buf,timespec* when)
    {
        timespec    now;
        if( !when ){
            when    = &now;
            clock_gettime(CLOCK_REALTIME,&now);
        }

        struct tm day;
        day   = *localtime(&when->tv_sec);

        if( buf )
            return sprintf(buf,"%02d:%02d:%02d.%06ld",day.tm_hour,day.tm_min,day.tm_sec,when->tv_nsec/1000); 
        return printf("%02d:%02d:%02d.%06ld",day.tm_hour,day.tm_min,day.tm_sec,when->tv_nsec/1000); 
    }

    static MonitorCtl* Instance();
    bool Run(bool runinserv,int interval_sec);
    void Stop();


    //  serialize op
    StreamStat* Get(ProtoStream *visitor);

    //  multithread op
    void Ret(StreamStat* item);

    //  only show one item or show all item
    void Dump( StreamStat* item );
};


enum ETestParserCmdId{
    TESTPARSER_CMD_ECHO,
    TESTPARSER_CMD_REVECHO,
    TESTPARSER_CMD_FLOOD,
    TESTPARSER_CMD_REVFLOOD,
    TESTPARSER_CMD_PUTFILE,
    TESTPARSER_CMD_GETFILE,
    TESTPARSER_CMD_MAX
};

struct TestParserParam;
typedef bool (*TESTPARSER_PRESEND)(TestParserParam *param,std::string& buf);
typedef bool (*TESTPARSER_POSTRECV)(TestParserParam *param,const char* buf,int len);

struct TestParserParam{
    uint32_t            blksz;
    uint32_t            num;
    char                strFilename[256];

    TESTPARSER_PRESEND  op_presend;
    TESTPARSER_POSTRECV op_postrecv;
    StreamStat*         stat;

    bool                tracksnd;
    void*               data;
    int                 fd;     //  used for TESTPARSER_CMD_PUTFILE/TESTPARSER_CMD_GETFILE
};


typedef bool (*TESTPARSER_INIT)(TestParserParam *param);
typedef void (*TESTPARSER_RELEASE)(TestParserParam *param);
struct TestParserItem{
    ETestParserCmdId    cmdid;
    const char*         cmdname;
    TESTPARSER_INIT     op_init;
    TESTPARSER_RELEASE  op_release;
};

#define RUNNINGENV_CLIENTCMD    "PROTOTEST_CLIENTCMD"
#define RUNNINGENV_CLIENTJOBNUM "PROTOTEST_JOBNUM"
#define RUNNINGENV_SERVADDR     "PROTOTEST_SERVIP"

bool TestParser_ExecClient(ProtoStream* stream,bool runintask);
bool TestParser_OnServerAccept(ProtoStream* stream);

int GetIntVal(int def,int min,int max,const char* arg,const char*envkey);
const char* GetStrVal(const char*def,const char* arg, const char* envkey);

bool TestParser_Init(bool isserv, char* ip,int *port,int argc, char ** argv);

void show_help(bool isserv,const char* appname);
#define CHECK_HELP(isserv,argc,argv)   {   \
    if( argc > 1 && (!strcmp(argv[1],"-?") || !strcmp(argv[1],"-h") || !strcmp(argv[1],"--help") ) ){ \
        show_help(isserv,argv[0]);  return 1; \
    } }


#endif

