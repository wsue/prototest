#include <string>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <assert.h>
#include <inttypes.h>
#include <string.h>
#include <sys/syscall.h>  
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "test_helper.h"




static char sTmpBuf[PKGSIZE_MAX];
static char sArgStr[1024];




bool Test_StartTask(pthread_t *thrid,void* (*start_routine)(void*),void *arg)
{
    pthread_t slave_tid;
    int ret = pthread_create(thrid ? thrid : &slave_tid, NULL, start_routine, arg);
    if( ret == 0 && !thrid )
	pthread_detach(slave_tid);
    return ret == 0;
}


MonitorCtl* MonitorCtl::Instance()
{
    static MonitorCtl*  p = NULL;
    if( !p )
        p               = new MonitorCtl;
    return p;
}

bool MonitorCtl::SetInterval(int interval_sec)
{
    if( interval_sec == 0 )
	interval_sec = MONITOR_DEFAULT_INTERVAL;


    timespec		now;
    struct itimerspec   new_value;
    clock_gettime(CLOCK_MONOTONIC, &now);
    uint64_t            nsec    = now.tv_nsec + interval_sec *1000*1000*1000;

    new_value.it_value.tv_sec   = now.tv_sec + nsec/1000000000;
    new_value.it_value.tv_nsec  = nsec %1000000000;
    new_value.it_interval.tv_sec = interval_sec;
    new_value.it_interval.tv_nsec = 0;

    int ret ;
    WRAP_SYSAPI(ret, timerfd_settime(timer_, TFD_TIMER_ABSTIME, &new_value, NULL));
    if( ret == -1){
	TESTAPP_SHOW_ERROR("set timer %d dur %d /%" PRIu64 "ns (%" PRIi64 ",%" PRIi64 ")fail start(%" PRIi64 ",%" PRIi64 "), ret:%d/%d\n",
		timer_,interval_sec,nsec,
		new_value.it_value.tv_sec,new_value.it_value.tv_nsec,
		now.tv_sec,now.tv_nsec,
		ret,errno);
	return false;
    }

    TESTAPP_SHOW_INFO("fd:%d timer<%ld %ld> + <%d >=<%ld %ld> ret:%d/%d\n",
	    timer_,now.tv_sec,now.tv_nsec,
	    interval_sec*1000,
	    new_value.it_value.tv_sec,new_value.it_value.tv_nsec,
	    ret,errno);
        
    clock_gettime(CLOCK_REALTIME,&last_);
    return true;
}

StreamStat* MonitorCtl::Get(ProtoStream *visitor){
    int i   = 0;
    if( num_ < JOBNUM_MAX) {
        for( ; i < JOBNUM_MAX && streams_[i].id != 0 ; i ++ ){
        }
    }
    else{
        i   = JOBNUM_MAX;
    }
    if( i >= JOBNUM_MAX ){
        printf("can not create new stream %08x, connect has full, cur num:%d\n",visitor->id(),num_);
        return NULL;
    }

    printf("create new stream %08x succ, index:%d num:%d\n",visitor->id(),i,num_);

    uint32_t streamid   = visitor->id();

    memset(&streams_[i],0,sizeof(streams_[i]));
    streams_[i].id          = streamid;
    streams_[i].visitor     = visitor;
    __sync_fetch_and_add(&num_,1);
    return &streams_[i];
}

//  multithread op
void MonitorCtl::Ret(StreamStat* item){
    printf("will release stream %08x,last stat:\n",item->id);
    Dump(item);

    item->id        = 0;
    item->visitor   = NULL;
    __sync_fetch_and_sub(&num_,1);
}


void MonitorCtl::Dump( StreamStat* item ){
    if( num_ <= 0 )
        return ;

    char        timestr[128]= "";
    timespec    now;
    StreamStat *pinfo = item ? item : streams_ ;

    clock_gettime(CLOCK_REALTIME,&now);
    uint64_t    dur = (now.tv_sec - last_.tv_sec) * 1000000 + (now.tv_nsec - last_.tv_nsec)/1000;
    Time2Str(timestr,&now);

    if( !item ){
        last_   = now;
    }

    printf("%s dur:%" PRIu64 "\n",timestr,dur);

    for( int i = 0; i < num_ ;pinfo++ ){
        if( pinfo->id == 0 )
            continue;

        uint64_t    pkts = (pinfo->pkts - pinfo->pkts_start);
        uint64_t    bytes = (pinfo->bytes - pinfo->bytes_start);
        if(pkts != 0 ){
            uint64_t    lastdurperpkt   = dur / pkts;
            uint64_t    bps             = (bytes *1000000)/dur;
            uint64_t    pktsz           = bytes/pkts;

            printf("\t%2d %s ID:%08x pktnum: %8" PRIu32 "(+%8" PRIu64 ") perpkt use: %3" PRIu64 " us sz: %4" PRIu64 ", "
                    " bytes: %8" PRIu32 " MB (+%8" PRIu64 "): %" PRIu64 " B/s %" PRIu64 " KB/s %" PRIu64 " MB/s"
                    " \n",
                    i,pinfo->tracksnd ? "WRITER":"READER",
                    pinfo->id, pinfo->pkts,pkts,lastdurperpkt,pktsz,
                    pinfo->bytes/(1024*1024),bytes,bps,bps/1024,bps/(1024*1024)
                  );
            pinfo->Sync();
        }
        else{
            printf("\t%02d %s ID:%08x pkgnum: %8" PRIu32 " 0 pkg, bytes: %8" PRIu32 "\n",
                    i,pinfo->tracksnd ? "WRITER":"READER",
                    pinfo->id, pinfo->pkts,pinfo->bytes);
        }

        if( item )
            break;

        i   ++;
    }
}

void MonitorCtl::DoRun()
{
    while(Wait()){
	Dump(NULL);
    }
}

void MonitorCtl::Task(MonitorCtl* ctl)
{
    ctl->DoRun();
}

bool MonitorCtl::Run(bool runinserv,int interval_sec)
{
    /*	server run in sask, and always run
     *	client only run when has stream
     */
    if( !SetInterval(interval_sec) )
	return false;

    if( runinserv ){
	Test_StartTask(&thrid_,(void* (*)(void*))Task,this);
    }
    else{
	DoRun();
    }
    return true;
}
    
void MonitorCtl::Stop(){
    int	tmpid	= timer_;
    timer_	= -1;
    close(tmpid);
    if( thrid_ != 0 ){
	void* p = NULL;
	pthread_join(thrid_,&p);
    }
}

int GetIntVal(int def,int min,int max,const char* arg,const char*envkey){
    if( envkey ){
        char    *p      = getenv(envkey);
        if( p )
            return strtoul(p,NULL,0);
    }

    int val = arg ? strtoul(arg,NULL,0) : def;

    if( val < min )
        val = min;
    else if( max > 0 && val > max )
        val = max;
    return val;
}

const char* GetStrVal(const char*def,const char* arg, const char* envkey){
    if( envkey ){
        char    *p      = getenv(envkey);
        if( p )
            return p;
    }

    return arg ? arg : def;
}


#define TEST_CMDSTR_ECHO        "ECHO"
#define TEST_CMDSTR_REVECHO     "REVECHO"
#define TEST_CMDSTR_FLOOD       "FLOOD"
#define TEST_CMDSTR_REVFLOOD    "REVFLOOD"
#define TEST_CMDSTR_PUTFILE     "PUT"
#define TEST_CMDSTR_GETFILE     "GET"

/*
 * 	CMD FLOW:	    client	server
 * 		ECHO		-- req  ->
 * 				<- succ --
 * 				echo --> 
 * 				<-- response 
 *		REVECHO		-- req  ->
 *		                <- echo --
 *		                response ->
 *		FLOOD		-- req  ->
 *				<- succ --
 *				-- flood ->
 *		REVFLOOD	-- req	->
 *				<- flood --
 *              PUT             -- req  ->
 *              		<- succ --
 *              		-- file content ->  (last package NO CONTENT)
 *              		<- finish
 *              GET		-- req  -->
 *              		<- file content  (last package NO CONTENT)
 *              		-- finish ->
*/
static void NullCmd_Release(TestParserParam *param);
static bool EchoCmd_InitSender(TestParserParam *param);
static bool EchoCmd_InitReceiver(TestParserParam *param);
static bool FloodCmd_InitSender(TestParserParam *param);
static bool FloodCmd_InitReceiver(TestParserParam *param);
static bool FileCmd_InitSender(TestParserParam *param);
static bool FileCmd_InitReceiver(TestParserParam *param);

//  client
static const TestParserItem       s_TestParser_Client[] = {
    {TESTPARSER_CMD_ECHO,       TEST_CMDSTR_ECHO,       EchoCmd_InitSender,     NullCmd_Release},
    {TESTPARSER_CMD_REVECHO,    TEST_CMDSTR_REVECHO,    EchoCmd_InitReceiver,   NullCmd_Release},
    {TESTPARSER_CMD_FLOOD,      TEST_CMDSTR_FLOOD,      FloodCmd_InitSender,    NullCmd_Release},
    {TESTPARSER_CMD_REVFLOOD,   TEST_CMDSTR_REVFLOOD,   FloodCmd_InitReceiver,  NullCmd_Release},
    {TESTPARSER_CMD_PUTFILE,    TEST_CMDSTR_PUTFILE,    FileCmd_InitSender,     NullCmd_Release},
    {TESTPARSER_CMD_GETFILE,    TEST_CMDSTR_GETFILE,    FileCmd_InitReceiver,   NullCmd_Release},
    {TESTPARSER_CMD_MAX,        NULL,                   NULL,                   NULL}
};

//  server
static const TestParserItem       s_TestParser_Server[] = {
    {TESTPARSER_CMD_ECHO,       TEST_CMDSTR_ECHO,       EchoCmd_InitReceiver,   NullCmd_Release},
    {TESTPARSER_CMD_REVECHO,    TEST_CMDSTR_REVECHO,    EchoCmd_InitSender,     NullCmd_Release},
    {TESTPARSER_CMD_FLOOD,      TEST_CMDSTR_FLOOD,      FloodCmd_InitReceiver,  NullCmd_Release},
    {TESTPARSER_CMD_REVFLOOD,   TEST_CMDSTR_REVFLOOD,   FloodCmd_InitSender,    NullCmd_Release},
    {TESTPARSER_CMD_PUTFILE,    TEST_CMDSTR_PUTFILE,    FileCmd_InitReceiver,   NullCmd_Release},
    {TESTPARSER_CMD_GETFILE,    TEST_CMDSTR_GETFILE,    FileCmd_InitSender,     NullCmd_Release},
    {TESTPARSER_CMD_MAX,        NULL,                   NULL,                   NULL}
};


static const TestParserItem* ParserItem_FindByCmdname(const TestParserItem *pitem,const char* cmdline,TestParserParam *param)
{
    const char  *pstart         = cmdline;
    while( isalnum(*pstart) )    pstart++;
    uint32_t         tokenlen    = pstart - cmdline;

    for( int i = 0; pitem->cmdname != NULL ; pitem++,i++ ){
        if( strlen(pitem->cmdname) == tokenlen
                && !memcmp(pitem->cmdname,cmdline,tokenlen) ){
            break;
        }
    }

    if( pitem->cmdname == NULL ){
        return NULL;
    }

    if( !param )
	return pitem;

    const char* p       = strstr(pstart,"BLKSZ:");
    if( p ){
        pstart          = strchr(p,':');
        pstart++;
        param->blksz    = strtoul(pstart,NULL,0);
    }

    p   = strstr(pstart,"NUM:");
    if( p ){
        pstart          = strchr(p,':');
        pstart++;
        param->num      = strtoul(pstart,NULL,0);
    }

    if( param->blksz == 0 || param->blksz >= PKGSIZE_MAX )
        param->blksz = DEFAULT_PKG_SIZE;

    if( pitem->cmdid == TESTPARSER_CMD_GETFILE || pitem->cmdid == TESTPARSER_CMD_PUTFILE ) {
	p   = strstr(pstart,"FILE:");
	if( p ){
	    pstart          = strchr(p,':');
	    pstart++;
	    while( isspace(*pstart) ) pstart ++;

	    if( *pstart ){
		strncpy(param->strFilename,pstart,sizeof(param->strFilename)-1);
		char *v = param->strFilename + strlen(param->strFilename) -1;
		while( v != param->strFilename 
			&& isspace(*v) )
		    *v -- = 0;
	    }
	}

	if( !param->strFilename[0] ){
	    return NULL;
	}
    }

    return pitem;
}


#define STR_FMTN(ret,buf,fmt,arg...)	{	\
    ret	= snprintf(buf+2,sizeof(buf)-3,fmt,##arg);	\
    if( ret >= 0 ){ 	ret	+= 2+1;			\
	uint16_t *psz = (uint16_t *)buf;  *psz	= htons(ret); \
    } \
}

static bool TestParser_Run(bool isserv,const char* cmdline,StreamStat* stat)
{
    std::string     body;

    //  1.  get running env
    TestParserParam param;
    memset(&param,0,sizeof(param));
    param.fd		= -1;
    param.stat         	= stat;

    const TestParserItem* pitem    = ParserItem_FindByCmdname(isserv ? s_TestParser_Server :s_TestParser_Client,cmdline,&param);
    if( !pitem ){
        TESTAPP_SHOW_ERROR("parse cmdline(%s) fail or cmd param invalid\n",cmdline);
        return false;
    }

    //  2.  init
    if( !pitem->op_init(&param) ){
        TESTAPP_SHOW_ERROR("init cmd %s fail, cmdparam(%s) invalid? \n",pitem->cmdname,cmdline);
        return false;
    }

    ProtoStream *stream = stat->visitor;
    stat->tracksnd                    = param.tracksnd;

    if( isserv && (!stat->tracksnd) ){
        stat->Inc(strlen(cmdline)+1);
    }

    //  3.  client send first req package, 
    //      server send ACK
    char    	cache[1024];
    int 	ret = 0;

    if( isserv ){
	if( pitem->cmdid == TESTPARSER_CMD_REVECHO
		|| pitem->cmdid == TESTPARSER_CMD_REVFLOOD
		|| pitem->cmdid == TESTPARSER_CMD_GETFILE ){
	    param.op_presend(&param,body);
	    if( body.empty() ){
		TESTAPP_SHOW_ERROR("prepare first pkg fail\n");
		return false;
	    }
	}
	else{
	    STR_FMTN(ret,cache,"SUCC");
	    body.assign(cache,ret);
	}
    }
    else{
        STR_FMTN(ret,cache,"%s BLKSZ:%u NUM:%u FILE:%s",
                pitem->cmdname,param.blksz,param.num,param.strFilename);
        body.assign(cache,ret);
    }

    stream->WriteN(body.data(),body.size());
    if( stat->tracksnd ){
        stat->Inc(body.size());
    }

    //	some client cmd need wait response after send cmd
    if( !isserv ){
	if(  pitem->cmdid == TESTPARSER_CMD_FLOOD 
		|| pitem->cmdid == TESTPARSER_CMD_PUTFILE ){
	    stream->ReadN(body);

	    if( !stat->tracksnd ){
		stat->Inc(body.size());
	    }
	}
    }

    //  4.  endter loop until disconnect
    char    title[32]   = "";
    sprintf(title,"TASK_%03d",stat->id);

    timespec    start;
    clock_gettime(CLOCK_REALTIME,&start);

    TESTAPP_SHOW_INFO("%s begin parse stream %p %08x blksz:%d num:%d file:%s cmd:%s<%s>\n",
            title,stream,stat->id,
            param.blksz,param.num,param.strFilename,
            pitem->cmdname,cmdline
            );


    while( stream->IsConnected() ){

        //  a.  recv
	if( param.op_postrecv ){
	    stream->ReadN(body);

	    if( !stat->tracksnd ){
		stat->Inc(body.size());
	    }
#if (defined TRACE_DETAIL) || (defined TRACE_SNDRECV)
	    TESTAPP_SHOW_INFO("%s <<<<     %lu<%s> \n",title,body.size(),body.c_str()+2);
#endif
	    if( !param.op_postrecv(&param,body.data(),body.size()) ){
		break;
	    }
	}

        //  b.  send
        if( param.op_presend ){
	    if( !param.op_presend(&param,body) || body.empty() ){
		break;
	    }

            stream->WriteN(body.data(),body.size());
            if( stat->tracksnd ){
                stat->Inc(body.size());
            }

#if (defined TRACE_DETAIL) || (defined TRACE_SNDRECV)
            TESTAPP_SHOW_INFO("%s     >>>> %lu<%s> \n",title,body.size(),body.c_str()+2);
#endif
        }

        if( param.num > 0 && stat->pkts > param.num ){
            break;
        }
    }

    //  5.  release param
    pitem->op_release(&param);
    timespec    now;
    clock_gettime(CLOCK_REALTIME,&now);
    uint64_t    dur = (now.tv_sec - start.tv_sec) * 1000000 + (now.tv_nsec - start.tv_nsec)/1000;
    TESTAPP_SHOW_INFO("%s FINISH parse stream %p %08x dur: %" PRIu64 " us\n",title,stream,stat->id,dur);

    return true;
}

static void ClientParseTask(StreamStat* stat)
{
    TestParser_Run(false,sArgStr,stat);
    
    ProtoStream *stream = stat->visitor;
    MonitorCtl::Instance()->Ret(stat);    
    delete stream;
}

static void ServerParseTask(StreamStat* stat)
{
    std::string     body;
    ProtoStream *stream = stat->visitor;
    stream->ReadN(body);
    if( !body.empty() ){
        assert(body[body.size()-1] == 0 );
        TestParser_Run(true,body.data()+2,stat);
    }

    MonitorCtl::Instance()->Ret(stat);    
    delete stream;
}

bool TestParser_OnServerAccept(ProtoStream* stream){
    StreamStat* stat = MonitorCtl::Instance()->Get(stream);
    if( !stat )
        return false;

    return Test_StartTask(NULL,(void* (*)(void*))ServerParseTask,stat);
}

bool TestParser_ExecClient(ProtoStream* stream,bool runintask){
    StreamStat* stat = MonitorCtl::Instance()->Get(stream);
    if( !stat )
        return false;

    if( runintask ){
        return Test_StartTask(NULL,(void* (*)(void*))ClientParseTask,stat);
    }
    else{
        ClientParseTask(stat);
    }

    return true;
}


/*-----------------------------------------------------------------------------------------------------------
 *
 *      interface
 *
 * --------------------------------------------------------------------------------------------------------*/
static bool NullCmd_PreSend(TestParserParam *param,std::string& buf)
{
    return true;
}

static bool NullCmd_PostRecv(TestParserParam *param,const char* buf,int len)
{
    return true;
}



static void NullCmd_Release(TestParserParam *param)
{
    if( param->data){
	free(param->data);
	param->data	= NULL;
    }

    if( param->fd >= 0 ){
        close(param->fd);
        param->fd    	= -1;
    }
}

static bool DefaultSender_Init(TestParserParam *param)
{
    char*	p 	= (char *)malloc(param->blksz);
    if( !p )
	return false;

    uint16_t*	psz	= (uint16_t *)p;
    *psz		= htons(param->blksz);

    memcpy(p +2 + 6,sTmpBuf,param->blksz -2 -6);
    p[param->blksz-1] = 0;
    if( param->blksz > 40 )
       p[40]		= 0;

    param->data		= p;
    return true;
}

static bool DefaultSender_PreSend(TestParserParam *param,std::string& buf)
{
    char*	p	= (char *)param->data;
    int ret	= sprintf(p+2,"%05d",param->stat->pkts);
    p[2+ret] = ' ';
    buf.assign(p,param->blksz);
    return true;
}

static bool EchoCmd_InitSender(TestParserParam *param)
{
    if(DefaultSender_Init(param)){
	param->tracksnd    	= true;
	param->op_presend   = DefaultSender_PreSend;
	param->op_postrecv  = NullCmd_PostRecv;
	return true;
    }
    return false;
}

static bool EchoCmd_InitReceiver(TestParserParam *param)
{
    param->tracksnd    	= false;
    param->op_presend   = NullCmd_PreSend;
    param->op_postrecv  = NullCmd_PostRecv;
    return true;
}

static bool FloodCmd_InitSender(TestParserParam *param)
{
    if(DefaultSender_Init(param)){
	param->tracksnd    = true;
	param->op_presend  = DefaultSender_PreSend;
    }
    return true;
}

static bool FloodCmd_InitReceiver(TestParserParam *param)
{
    param->tracksnd    	= false;
    param->op_postrecv  = NullCmd_PostRecv;
    return true;
}


static bool FileCmd_SenderWaitAck(TestParserParam *param,const char* buf,int len)
{
    if( param->fd >= 0 ){
	TESTAPP_SHOW_WARNNING("recv receiver ack %d<%s>,will close\n",len,buf+2);
	close(param->fd);
	param->fd    = -2;
	return true;
    }
    return false;
}

static bool FileCmd_ReceiverSendAck(TestParserParam *param,std::string& buf)
{
    if( param->fd >= 0 ){
	char	cache[]	= "  FINISH";
	uint16_t*	psz	= (uint16_t *)cache;
	*psz		= htons(sizeof(cache));
	buf.assign(cache,sizeof(cache));
	return true;
    }

    return false;
}

static bool FileCmd_PreSend(TestParserParam *param,std::string& buf)
{
    if( param->fd == -2 ){
	buf.clear();
	return true;
    }

    char    cache[param->blksz];

    int     ret ;
    WRAP_SYSAPI(ret,read(param->fd,cache+2,param->blksz -2));
    if( ret >= 0 ){
	ret		+= 2;
	uint16_t* psz 	= (uint16_t *)cache;
	*psz		= htons(ret);
        buf.assign(cache,ret);
	if( ret == 2 ){
	    TESTAPP_SHOW_WARNNING("succ read all content\n");
	    param->op_presend     = NULL;
	    param->op_postrecv    = FileCmd_SenderWaitAck;
	}
        return true;
    }

    buf.clear();

    TESTAPP_SHOW_WARNNING("read file %s:%d fail, ret:%d errno:%d will close\n",
            param->strFilename,param->fd,ret,errno);
    close(param->fd);
    param->fd    = -1;
    ProtoStream *stream = param->stat->visitor;
    stream->Close(false);
    return false;
}

static bool FileCmd_PostRecv(TestParserParam *param,const char* buf,int len)
{
    int     ret = 0;

    if( len >= 2 ){
	if( param->fd < 0 ){
	    char    newname[1024];
	    char*p  = strrchr(param->strFilename,'/');
	    if( p )
		p++;
	    else
		p   = param->strFilename;

	    time_t	sec = time(NULL);
	    struct tm   day = *localtime(&sec);
	    sprintf(newname,"recvfile_%02d%02d%02d%02d%02d_%s",day.tm_mon,day.tm_mday,day.tm_hour,day.tm_min,day.tm_sec,p);

	    int                 fd = open(newname,O_WRONLY|O_CREAT|O_TRUNC);
	    if( fd == -1 ){
		TESTAPP_SHOW_WARNNING("write file %s:%d sz:%d -2 open fail, ret:%d errno:%d will close\n",
			param->strFilename,param->fd,len, ret,errno);
		return false;
	    }

	    param->fd           = fd;
	}

	if( len == 2 ){
	    TESTAPP_SHOW_WARNNING("succ finish recv all content\n");
	    param->op_presend     = FileCmd_ReceiverSendAck;
	    param->op_postrecv    = NULL;
	    return true;
	}

	WRAP_SYSAPI(ret,write(param->fd,buf+2,len-2));

	if( ret > 0 ){
	    return true;
	}
    }

    TESTAPP_SHOW_WARNNING("write file %s:%d sz:%d -2 fail, ret:%d errno:%d will close\n",
            param->strFilename,param->fd,len, ret,errno);
    close(param->fd);
    param->fd    = -1;
    ProtoStream *stream = param->stat->visitor;
    stream->Close(false);
    return false;
}


static bool FileCmd_InitSender(TestParserParam *param)
{
    param->fd           = -1;
    int fd              = open(param->strFilename,O_RDONLY);
    if( fd == -1 ){
        return false;
    }

    param->fd           = fd;
    param->tracksnd     = true;
    param->op_presend   = FileCmd_PreSend;
    return true;
}

static bool FileCmd_InitReceiver(TestParserParam *param)
{
    param->fd           = -1;


    param->tracksnd     = false;
    param->op_postrecv  = FileCmd_PostRecv;
    return true;
}


static void InitPrnStr(){
    uint32_t	i	= 0;
    for( int j = 32; j <= 126 ; j++,i++ ){	sTmpBuf[i] = j;    }

    uint32_t blksz	= i;
    uint32_t offset	= blksz;
    for( ; offset + blksz < sizeof(sTmpBuf);  ){
	memcpy(sTmpBuf + offset, sTmpBuf, blksz);
	offset += blksz;
	blksz  *= 2;
    }

    memcpy(sTmpBuf + offset, sTmpBuf, sizeof(sTmpBuf) - offset );
}

bool TestParser_Init(bool isserv, char* ip,int *port,int argc, char ** argv)
{
    InitPrnStr();

    if( isserv ){
        if( ip )
            ip[0]   = 0;
    }
    else{
	const char* penv	= NULL;
	int i 			= 1;
	if( argc > 1 && isdigit(argv[1][0]) )
	    i			++;

	if( argc > i ){
	    for( ; i < argc ; i++ ){
		strcat(sArgStr,argv[i]);
		strcat(sArgStr," ");
	    }
	}
	else{
	    penv  = GetStrVal("ECHO BLKSZ:1200 NUM:0 FILE:",NULL,RUNNINGENV_CLIENTCMD);
	    if( penv ){
		strcpy(sArgStr,penv);
	    }
	}

	if( !sArgStr[0] ){
	    TESTAPP_SHOW_ERROR("run cmd not found, you need set: %s=\"cmdname BLKSZ:blocksize NUM:sendnum FILE:get/put_file_full_name\"\n",RUNNINGENV_CLIENTCMD);
	    return false;
	}
	
	TestParserParam param;
	if(! ParserItem_FindByCmdname(s_TestParser_Client,sArgStr,&param) ){
	    TESTAPP_SHOW_ERROR("running %s %s no match command or param invalid, stop. use -? to get help list\n",
		    penv ?"env " RUNNINGENV_CLIENTCMD : "arg", sArgStr);
	    return false;
	}

	const char *servaddr = GetStrVal("127.0.0.1",NULL, RUNNINGENV_SERVADDR);
	strcpy(ip,servaddr);
    }

    *port   = SERVER_PORT;

    MonitorCtl::Instance();

    return true;
}

void show_help(bool isserv,const char* appname)
{
    if( !isserv ){
	printf("%s running env:\n"
		"\t%s=\"server_ip_address\"\n"
		"\t%s=stream_num\n"
		"\t%s=\"cmdstr BLKSZ:each_packet_size NUM:num_of_packet_sent FILE:filename_to_put_get\"\n"
		"\t%s 's value can also input in running param\n"
		"\tcmdstr include:\n"
		""
		,appname,
		RUNNINGENV_SERVADDR,
		RUNNINGENV_CLIENTJOBNUM,
		RUNNINGENV_CLIENTCMD,
		RUNNINGENV_CLIENTCMD
	      );

	const TestParserItem* pitem = s_TestParser_Client;
	while( pitem->cmdname ){
	    printf("\t\t%s\n",pitem->cmdname);
	    pitem ++;
	}
	printf("\n");
    }
    else{
        printf("%s not use running param\n",appname);
    }
}

