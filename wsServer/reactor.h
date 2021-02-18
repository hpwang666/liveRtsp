#ifndef _REACTOR_H
#define _REACTOR_H

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <event2/event.h>

#include "bio_buf.h"


#define REACTOR_WOULDBLOCK (errno == EWOULDBLOCK || errno == EINTR || errno == EAGAIN)
#define REACTOR_InProgress (errno == EINPROGRESS)
#define REACTOR_ConnRefused (errno == ECONNREFUSED)

#define BIO(R,A,G) ((R->bio_call))(R,A,G) 
typedef enum {action_ACCEPT, action_READ, action_WRITE,action_CONNECT,action_CLOSE } reactor_action_t;
typedef struct reactor_fd_st *reactor_fd_t; 
typedef int (*bio_handler)(reactor_fd_t rfd,reactor_action_t e, void *arg);

 
 
 typedef enum {
	type_CLOSED = 0x00,
	type_NORMAL = 0x01,
	type_LISTEN = 0x02,
	type_CONNECT = 0x10,
	type_CONNECT_READ = 0x11,
	type_CONNECT_WRITE = 0x12,
	type_WAITING = 0x20
} reactor_fd_type;


struct reactor_fd_st{
	reactor_fd_type type;
	int fd;
	
	bio_handler bio_call;
	void *arg	;

	struct event *evRead;
	struct event *evWrite;
	struct event_base *base;
};



reactor_fd_t setfd(struct event_base *,int ,reactor_fd_type ,bio_handler , void *);
int removefd(reactor_fd_t rfd);
int processAccept(reactor_fd_t rfd);
int processRead(reactor_fd_t rfd);
void _canRead(int fd, short what, void *arg);



struct event_base *reactorCreate(void);
int reactorLoop(struct event_base *base);
int reactorLoopAdd(struct event_base *base);
int  reactorLoopOnce(struct event_base *base, int milisecond);
//int reactorRead();
//int reactorWrite(reactor_fd_t rfd);
reactor_fd_t reactorListen(struct event_base *base, int port, bio_handler app, void *arg);
reactor_fd_t reactorConnect(struct event_base *base, char *ip,int port, bio_handler app, void *arg);
int reactorWrite(reactor_fd_t rfd);
int reactorClose(reactor_fd_t rfd);
int reactorLoopBreak(struct event_base *base);

typedef struct reactorTimer_st *reactorTimer_t;
typedef int (*timer_handler)(reactorTimer_t, void *arg);

struct reactorTimer_st{
	timer_handler timer_call;
	void *arg;
	struct event *evTimer;
	struct event_base *base;
};

void _event_timeout(evutil_socket_t fd, short flag, void *arg);
reactorTimer_t reactorTimerCreate(struct event_base *base,timer_handler app,void *arg) ;
int reactorTimerAdd(reactorTimer_t,int) ;
int reactorTimerUpdate(reactorTimer_t,int) ; 
int reactorTimerDel(reactorTimer_t)  ; 
int reactorTimerFree(reactorTimer_t)  ;
#endif
