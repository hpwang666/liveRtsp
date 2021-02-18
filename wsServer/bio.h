#ifndef _BIO_H
#define _BIO_H
  
#include "reactor.h"
#include <event2/event.h>
typedef enum {
    /* mandatory callback */
    bio_READ ,        /* ¶ÁÍê°üÍ·, get packet body len data=read_ptr*/
    /* optional callback */
    bio_CLOSED,             /* connection will be closed */
	bio_PKT_WRITTEN,		/* packet written out */
	bio_PKT_TIMEOUT,		/* packet not send */
	bio_WANT_READ,			/* try continue reading after delayed */
	bio_CONNECTED
} bio_event_t; 

typedef enum {NOINIT=0,INIT=1,JOIN,CAM} ws_type;

typedef enum{bio_SERVER, bio_CLIENT} bio_type;
typedef enum{RTSP_BAD=-1,RTSP_MIN=0,RTSP_TXT=1,RTSP_BIN} RTSP_TYPE;

typedef struct bioConn_st* bioConn_t;
typedef int (*app_handler)(bioConn_t c, bio_event_t e, void *arg);
typedef struct wsServer_st* wsServer_t;
typedef struct wsServerList_st *wsServerList_t;

struct bioConn_st{
	reactor_fd_t rfd;
	
	bioBuf_t readBuf;
	bio_type type;
	char 		local_ip[100];
	int 		local_port;
	char 		peer_ip[100];
	int 		peer_port;
	
	app_handler app_call;
	void *arg;

};

struct wsServerList_st{
	wsServer_t head;
	wsServer_t tail;
	wsServer_t cache;
	int activesize;
	int cachesize;
};  

struct wsServer_st{
	bioConn_t wsConn;
	char *wsBuf;//4096
	ws_type type;
	int seq;
	char session[128];
	wsServer_t next;
	wsServer_t prev;
};  
  
bioConn_t wsServerCreate(struct event_base *base,  int port, app_handler app, void *arg);
wsServer_t camClientCreate(wsServerList_t wsServerList,  char *ip,int port, app_handler app, void *arg);
int process_response(wsServerList_t wsServerList,reactor_fd_t rfd,char *respBuf);
int  srchCamRespHead(bioBuf_t bioBuf);
RTSP_TYPE getCamRespLen(bioBuf_t bioBuf, int *PkgLen);
int bioServerFree(bioConn_t Conn);
int _bio_server_call(reactor_fd_t rfd,reactor_action_t a,void *arg);
int _bio_client_call(reactor_fd_t rfd,reactor_action_t a,void *arg);
int  bioRead(wsServerList_t wsServerList,reactor_fd_t rfd);
int  bioWrite(bioConn_t c,void *data,int len);
int _bio_can_write(bioConn_t c);
int bioConnFree(wsServerList_t wsServerList,reactor_fd_t rfd);
void bioSetConnInfo(bioConn_t conn, int fd);
void keepalive(int sock);
#endif