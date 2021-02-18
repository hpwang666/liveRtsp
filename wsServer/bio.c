/*
	author:wwp
	date:2019/5/17
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "bio.h"
#include "reactor.h"
#include "bio_buf.h"
#include "util/util.h"


#include "websocket_common.h"
#ifndef TCP_KEEPIDLE
#define TCP_KEEPIDLE            4       /* Start keeplives after this period */
#define TCP_KEEPINTVL           5       /* Interval between keepalives */
#define TCP_KEEPCNT             6       /* Number of keepalives before death */
#endif

 
#undef  _DEBUG
//#define _DEBUG
#ifdef _DEBUG
	#define debug(...) printf(__VA_ARGS__)
#else
	#define debug(...)
#endif 
 
 
int client_handler(bioConn_t c, bio_event_t ev, void *arg)
{
	//bioBuf_t bioBuf= c->bioBufList->head;
	switch(ev){
	case bio_READ:
		//printf("got %d bytes\n",bioBuf->len);
		return 1;
	case bio_CLOSED:
		printf("CAM:closed,client=%s:%d\n", c->peer_ip,c->peer_port);
		return 0;
	case bio_CONNECTED:
		printf("CAM:Connected,client=%s:%d\n", c->peer_ip,c->peer_port);
		return 0;
	default:
		return 0;
	}
	return 0;
}


wsServer_t findConn(wsServerList_t wsServerList,reactor_fd_t rfd)//通过rfd来找到自己的Conn
{
	wsServer_t wsFind = wsServerList->head;
	while(wsFind != NULL)
	{
		if(wsFind->wsConn->rfd == rfd ) {
			//printf("ok findConn port %d:[%d]\r\n",wsFind->type,wsFind->wsConn->peer_port);
			return wsFind;
		}
		 
		wsFind=wsFind->next;
	}
	return NULL;
}

wsServer_t findSession(wsServerList_t wsServerList,char * session,ws_type type)//通过session来确定是哪个组的data通道
{
	wsServer_t wsFind = wsServerList->head;
	while(wsFind != NULL)
	{
		if(strncmp(wsFind->session,session,strlen(session)) == 0) {
			if(wsFind->type == type )
				return wsFind;
		}
		wsFind=wsFind->next;
	}
	return NULL;
}

int updateSeq(wsServerList_t wsServerList,char *session,int seq)
{
	
	wsServer_t wsFind = wsServerList->head;
	while(wsFind != NULL)
	{
		if(strncmp(wsFind->session,session,strlen(session)) == 0) {
			wsFind->seq = seq ;
		}
		wsFind=wsFind->next;
	}
	return 0;
}


bioConn_t wsServerCreate(struct event_base *base,  int port, app_handler app, void *arg)
{
	
	wsServerList_t wsServerList = calloc(1, sizeof(struct wsServerList_st));
	
	wsServer_t ws=calloc(1, sizeof(struct wsServer_st));
	bioConn_t c = calloc(1, sizeof(struct bioConn_st));
	c->rfd = reactorListen(base, port, _bio_server_call, wsServerList);//只是为了将app传入
    c->app_call= app;
    c->arg = arg;
	ws->wsConn = c;
	
	ws->next =NULL;
	ws->prev =NULL;
	wsServerList->head = wsServerList->tail = ws;
	wsServerList->activesize++;
	return c;
}

//rtsp cam client 
wsServer_t camClientCreate(wsServerList_t wsServerList,  char *ip,int port, app_handler app, void *arg)
{	
	wsServer_t newWS;
	
	if(wsServerList->cache){
		newWS= wsServerList->cache;
		wsServerList->cache = wsServerList->cache->next;
		wsServerList->cachesize--;
		debug("found in cache\r\n");
	}
	else {
		debug("found in calloc\r\n");
		newWS = (wsServer_t)calloc(1, sizeof( struct wsServer_st ) );
		newWS->wsConn = (bioConn_t) calloc(1, sizeof(struct bioConn_st));
		newWS->wsBuf= (char*)  calloc(1, 4096);
		newWS->wsConn->readBuf = bio_buf_new(8*4096);
	}
	newWS->prev =NULL;
	newWS->next = NULL;
	memset(newWS->wsBuf,'\0', 4096);
	memset(newWS->session,'\0', 128);
	bio_buf_init(newWS->wsConn->readBuf);
	newWS->type = NOINIT;
	newWS->seq = 0;
	
	wsServerList->tail->next = newWS; //add the new to the tail
	newWS->prev = wsServerList->tail;
	wsServerList->tail = newWS;
	wsServerList->activesize ++;
	
	newWS->wsConn->rfd = reactorConnect(wsServerList->head->wsConn->rfd->base, ip,port, _bio_client_call, wsServerList);//只是为了将app传入
    newWS->wsConn->app_call= app;
    newWS->wsConn->arg = arg;
	newWS->wsConn->type = bio_CLIENT;
	
	return newWS;
}



int bioServerFree(bioConn_t Conn)
{
	close(Conn->rfd->fd);
	free(Conn);
	return 0;
}

int _bio_server_call(reactor_fd_t rfd,reactor_action_t a,void *arg)
{
	wsServerList_t wsServerList = (wsServerList_t)arg;
	bioConn_t newConn; 
	wsServer_t newWS,wsHead,ws;
	wsHead = wsServerList->head;
	
	switch(a){
		case action_READ:
			return bioRead(wsServerList,rfd);
		case action_WRITE:
			ws = findConn( wsServerList, rfd);
			return _bio_can_write(ws->wsConn);
		case action_CLOSE:
            bioConnFree(wsServerList,rfd);
            return 0;
		case action_ACCEPT://newfd 已经分配了read event
		{
			if(wsServerList->cache){
				newWS= wsServerList->cache;
				wsServerList->cache = wsServerList->cache->next;
				wsServerList->cachesize--;
				debug("found in cache\r\n");
			}
			else {
				debug("found in calloc\r\n");
				newWS = (wsServer_t)calloc(1, sizeof( struct wsServer_st ) );
				newWS->wsConn = (bioConn_t) calloc(1, sizeof(struct bioConn_st));
				newWS->wsBuf= (char*)  calloc(1, 4096);
				newWS->wsConn->readBuf = bio_buf_new(8*4096);
			}
			
			newWS->prev =NULL;
			newWS->next = NULL;
			
			wsServerList->tail->next = newWS; //add the new to the tail
			newWS->prev = wsServerList->tail;
			wsServerList->tail = newWS;
			wsServerList->activesize ++;
			
			memset(newWS->wsBuf,'\0', 4096);
			memset(newWS->session,'\0', 128);
			bio_buf_init(newWS->wsConn->readBuf);
			newWS->type = NOINIT;
			newWS->seq = 0;
			
			newConn = newWS->wsConn;
			newConn->rfd = rfd;
			newConn->type = bio_SERVER;
			newConn->app_call = wsHead->wsConn->app_call;
			newConn->arg = wsHead->wsConn->arg;
			
			
			rfd->arg = wsServerList;//exchange arg 
			
			bioSetConnInfo(newConn,newConn->rfd->fd);
			keepalive(rfd->fd);
			newConn->app_call(newConn,bio_CONNECTED,newConn->arg);
		}
		default:break;
	}
	return 0;
}


int _bio_client_call(reactor_fd_t rfd,reactor_action_t a,void *arg)
{
	wsServerList_t wsServerList = (wsServerList_t)arg;
	int ret;
	wsServer_t wsInit;
	wsServer_t wsCam = findConn( wsServerList, rfd);
	bioConn_t c = wsCam->wsConn;
	
	switch(a){
		case action_READ:
			return bioRead(wsServerList,rfd);;
		case action_WRITE:
			return _bio_can_write(c);
		case action_CONNECT:
			if(-1 == _bio_can_write(c))
			return -1;
			else{
				c->rfd = rfd;
				bioSetConnInfo(c,c->rfd->fd);
				keepalive(c->rfd->fd);
				c->app_call(c,bio_CONNECTED,c->arg);
				
				wsInit = findSession(wsServerList,wsCam->session,INIT);
				if(wsInit)
				{
					memset(wsInit->wsBuf,'\0',4096);
					ret = ws_genWspOK(wsInit->wsBuf,wsCam->session,wsInit->seq);
					bioWrite(wsInit->wsConn,wsInit->wsBuf,ret);//连接成功发送channel，这时候client会重新添加data通道
				}
				
				return 0;
			}
		case action_CLOSE:
			bioConnFree(wsServerList,rfd);
            return 0;
		default:
			break;
	}
	return 0;
}

int  bioRead(wsServerList_t wsServerList,reactor_fd_t rfd)
{
	int len;
	int ret = 0;
	WS_DATA_TYPE data_type;
	RTSP_TYPE rtspType;
	char *respBuf=NULL;
	int wsPkgLen=0;
	int rtpPkgLen=0;
	bioBuf_t bioBuf;
	wsServer_t wsInit,wsJoin;
	
	wsServer_t ws = findConn( wsServerList, rfd);
	bioConn_t c = ws->wsConn;
	bioBuf = c->readBuf;
	respBuf = ws->wsBuf;
	if(c->type == bio_SERVER){
		bio_buf_extend(bioBuf, 4096);
		len=recv(rfd->fd,bioBuf->tail,4096,0);
		if(len<=0){
			//debug("BIO:close when read\r\n");
			reactorClose(rfd);
		}
		else{
			bioBuf->size += len;
			bioBuf->tail += len;
			ret = c->app_call(c,bio_READ,c->arg);
			memset(respBuf,'\0',4096);
			data_type = ws_dePackage(bioBuf->head,len,respBuf,&wsPkgLen);
			if(data_type == WDT_MINDATA){
				if(strncmp(bioBuf->head, "GET", 3) == 0){	//握手,建立连接
					if(strstr(bioBuf->head,"Sec-WebSocket-Protocol: control")){
						ws->type = INIT;
						ws_genChannel(c->peer_ip,c->peer_port,ws->session);
					}
					if(strstr(bioBuf->head,"Sec-WebSocket-Protocol: data")){
						ws->type = JOIN;
					}
						
					ws_serverRespToClient(bioBuf->head,respBuf);
					bioWrite(c,respBuf,strlen(respBuf));
				}
			}
			
			if(data_type == WDT_TXTDATA){
				debug("<<<%s",respBuf);
				process_response(wsServerList, rfd,respBuf);
			}
			if(data_type == WDT_ERR);
			
			bio_buf_consume(bioBuf, len);
		}
		return 1;
	}
	else{ //from cam
		bio_buf_extend(bioBuf, 4096);
		len=recv(rfd->fd,bioBuf->tail,4096,0);
		if(len<=0){
			//debug("BIO:close when read\r\n");
			reactorClose(rfd);
		}
		bioBuf->size += len;
		bioBuf->tail += len;
		
		rtspType = getCamRespLen(bioBuf, &rtpPkgLen);
		while(rtspType >0 )
		{
			if(rtspType == RTSP_BIN){
				wsJoin = findSession(wsServerList,ws->session,JOIN);
				if(wsJoin){
					ret = ws_genRtp(respBuf,bioBuf->head,rtpPkgLen,WDT_BINDATA);
					bioWrite(wsJoin->wsConn,respBuf,ret);
				}	
			}
			if(rtspType == RTSP_TXT){
				memset(respBuf,'\0',4096);
				memcpy(respBuf,bioBuf->head,rtpPkgLen);
				debug(">>>%s",respBuf);
				ret = ws_genWspResp(respBuf,bioBuf->head,rtpPkgLen,ws->seq,WDT_TXTDATA);
				wsInit=findSession(wsServerList,ws->session,INIT);
				if(wsInit)
					bioWrite(wsInit->wsConn,respBuf,ret);
			}
					
			bio_buf_consume(bioBuf, rtpPkgLen);	
			rtspType = getCamRespLen(bioBuf, &rtpPkgLen);
		}	
		if( rtspType == RTSP_BAD){
			printf(">>>>>>>bad package\r\n");
			ret = srchCamRespHead(bioBuf);
			bio_buf_consume(bioBuf, ret);	
		}
	}
	return 0;
}


int  srchCamRespHead(bioBuf_t bioBuf)
{
	unsigned char rtpHead[2] = {0x24,0x00};
	unsigned char *data = (unsigned char*)bioBuf->head;
	int size = bioBuf->size;
	
	unsigned char *p;
	p = (unsigned char *)memmem(data, size, rtpHead, 2);
	if (p) return (p-data); 
	
	p = (unsigned char *)memmem(data, size, "RTSP", 4);
	if (p) return (p-data); 
	
	return size;
}


RTSP_TYPE getCamRespLen(bioBuf_t bioBuf, int *PkgLen)
{
	int size = bioBuf->size;
	char *data = bioBuf->head;
	int headlen;
	char* q;
	*PkgLen =0;
	if(size < 4)
		return RTSP_MIN;
	if(data[0] == '$'){
		// this is an rtp packet.
		int len = (data[2] & 0xFF) << 8 | (data[3] & 0xFF);
		
		if(size >=(len + 4) ){
			*PkgLen = len + 4;
			return RTSP_BIN;
		}
		else {
			return RTSP_MIN;
		}
		
	} else{
		// rtsp response data.
		if(strncmp(data, "RTSP", 4)!=0)
			return RTSP_BAD;
			
		char *p = ( char *)memmem((void*)data, size, "\r\n\r\n", 4);
		if(!p)
			return RTSP_MIN;
		
		headlen = p - data;
		q = memmem(data, headlen, "\r\nContent-Length:", 17);
		if(!q)
			q = memmem(data, headlen, "\r\nContent-length:", 17);
		*PkgLen = headlen + 4 + (q ? atoi(q + 17) : 0);
		return RTSP_TXT;
	}
}


int process_response(wsServerList_t wsServerList,reactor_fd_t rfd,char *respBuf)
{
	char host[64];
	int port,seq,contentLength;
	char *pHead;
	wsServer_t wsCam;
	wsServer_t ws = findConn( wsServerList, rfd);
	bioConn_t c = ws->wsConn;
	if(strncmp(respBuf, "WSP/1.1 INIT", 12) == 0)
	{
		pHead = strstr(respBuf,"\r\n");
		pHead = strstr(pHead+2,"\r\n");
		pHead = strstr(pHead+2,"host: ")+6;
		sscanf(pHead,"%s",host);
		
		pHead =  strstr(pHead,"\r\n")+2;
		pHead = strstr(pHead,"port: ")+6;
		port = atoi(pHead);
		
		pHead =  strstr(pHead,"\r\n")+2;
		pHead = strstr(pHead,"seq: ")+5;
		seq = atoi(pHead);
		
		wsCam = camClientCreate( wsServerList,  host,port, client_handler, NULL);
		wsCam->type = CAM;
		memcpy(wsCam->session,ws->session,strlen(ws->session));
		updateSeq(wsServerList,ws->session,seq);
	}
	if(strncmp(respBuf, "WSP/1.1 JOIN", 12) == 0) 
	{
		pHead = strstr(respBuf,"channel: ")+9;
		memcpy(ws->session,pHead,40);
		
		pHead = strstr(respBuf,"\r\n");
		pHead = strstr(pHead+2,"\r\n");
		pHead = strstr(pHead+2,"seq: ")+5;
		seq = atoi(pHead);
		
		memset(respBuf,'\0',4096);
		ws_genWspOK(respBuf,NULL,seq);
		updateSeq(wsServerList,ws->session,seq);
		bioWrite(c,respBuf,strlen(respBuf));//send wsp OK
	}
	if(strncmp(respBuf, "WSP/1.1 WRAP", 12) == 0)
	{
		pHead = strstr(respBuf,"\r\n");
		pHead = strstr(pHead+2,"contentLength: ")+15;
		contentLength = atoi(pHead);
		
		pHead = strstr(pHead,"\r\n");
		pHead = strstr(pHead+2,"seq: ")+5;
		seq = atoi(pHead);
		pHead = strstr(pHead,"\r\n");//seq
		pHead = strstr(pHead+2,"\r\n");
		
		pHead+=2;//content
		updateSeq(wsServerList,ws->session,seq);
		wsCam = findSession(wsServerList,ws->session,CAM);
		if(wsCam)
		{
			memset(wsCam->wsBuf,'\0',4096);
			memcpy(wsCam->wsBuf,pHead,contentLength);
			bioWrite(wsCam->wsConn,wsCam->wsBuf,contentLength);
		}
		
	}
	return 0;
}

int bioWrite(bioConn_t c,void *data,int len)
{	
	send(c->rfd->fd, data, len, MSG_NOSIGNAL);
	return 0;
}


//只用来测试连接是否断开，是否能够连接上，写操作不能使用触发方式，会导致触发失败
int _bio_can_write(bioConn_t c)
{
    int err;
    socklen_t errlen = sizeof(err);
	getsockopt(c->rfd->fd, SOL_SOCKET, SO_ERROR, &err, &errlen);
	if (err) {
		// have some error on socket.
		printf("BIO:close when write\r\n");
		//reactorClose(c->rfd);
        return -1;
	}
	return 0;
}

int bioConnFree(wsServerList_t wsServerList,reactor_fd_t rfd)
{
	wsServer_t wsFind;
	bioConn_t c = NULL;
	wsFind = findConn( wsServerList, rfd);
	if (wsFind == NULL) return -1;
	
	
	c = wsFind->wsConn;
	
	c->app_call(c,bio_CLOSED,c->arg);//启用一次app close
		
	if(wsFind->prev !=NULL)//if head
		wsFind->prev->next = wsFind->next;
	else wsServerList->head = wsFind->next;

	if(wsFind->next!=NULL)//if tail
		wsFind->next->prev = wsFind->prev;
	else wsServerList->tail = wsFind->prev;
	
	wsFind->next = wsServerList->cache;
	wsFind->prev = NULL;
	wsServerList->cache = wsFind; //into cache
	wsServerList->cachesize++;
	wsServerList->activesize--;
	
	wsFind = findSession(wsServerList,wsFind->session,3);
	if(wsFind){
		printf("find cam\r\n");
		reactorClose(wsFind->wsConn->rfd);
	}
	else printf("no cam\r\n");
#if 0	
	for(index=1;index<4;index++){
		wsFind = findSession(wsServerList,wsFind->session,index);
		if(wsFind){
			reactorClose(wsFind->wsConn->rfd);
		}
	}
#endif
	return 0;
}


void bioSetConnInfo(bioConn_t conn, int fd)
{
    struct sockaddr_storage sa = {0};
    socklen_t namelen = sizeof(sa);
    char peer_ip[200] = {'\0'};
    char local_ip[200] = {'\0'};
    getsockname(fd, (struct sockaddr*)&sa, &namelen);
    j_inet_ntop(&sa, local_ip, sizeof(local_ip));
    if(0 == strcmp(local_ip, "unix:@")){
    	snprintf(local_ip, sizeof(local_ip), "anonymous-sock-%d", fd);
    }
    strncpy(conn->local_ip, local_ip, sizeof(conn->local_ip) - 1);
    conn->local_port = j_inet_getport(&sa);

    /* Server mode: get remote info by fd,
	   Client mode: known when connecting */
    
    memset(&sa, 0, namelen);
	getpeername(fd, (struct sockaddr *) &sa, &namelen);
	j_inet_ntop(&sa, peer_ip, sizeof(peer_ip));
	strncpy(conn->peer_ip, peer_ip, sizeof(conn->peer_ip) - 1);
	conn->peer_port = j_inet_getport(&sa);
    
}

void keepalive(int sock)
{
	int keep = 1;
	int keepidle = 30;
	int keepintvl = 10;
	int keepcnt = 3;
	setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char*)&keep, sizeof(keep));
	setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, (char*)&keepidle, sizeof(keepidle));
	setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, (char*)&keepintvl, sizeof(keepintvl));
	setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, (char*)&keepcnt, sizeof(keepcnt));
}