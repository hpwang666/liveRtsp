/*
	author:wwp
	date:2019/5/17
*/
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <event2/event.h>

#include "util/util.h"
#include "reactor.h"

#undef  _DEBUG
//#define _DEBUG
#ifdef _DEBUG
	#define debug(...) printf(__VA_ARGS__)
#else
	#define debug(...)
#endif 
 
 
static void _dummy(evutil_socket_t fd, short f, void* arg){}
static void _dummy_persistent(evutil_socket_t fd, short f, void* arg){
	struct timeval tv = {86400, 0};
	event_add(arg, &tv);
}

int reactorLoopAdd(struct event_base *base)
{
	static struct event *ev_loop;
	struct timeval tv = {86400, 0};
	ev_loop=event_new(base, 0, EV_TIMEOUT,_dummy_persistent,ev_loop);
	event_add(ev_loop, &tv);
	do{
		event_base_loop(base, 0);
		usleep(10000);
	}while(1);
	return 0;
}

int  reactorLoopOnce(struct event_base *base, int milisecond)
{
	struct event *ev_loop;
	if(milisecond > 0){
		struct timeval tv = {0};
		if(milisecond > 1000){
			tv.tv_sec = milisecond / 1000;
			milisecond %= 1000;
		}
		tv.tv_usec = milisecond * 1000;
		ev_loop=event_new(base, 0, EV_TIMEOUT,_dummy,NULL);
		event_add(ev_loop, &tv);
		event_base_loop(base, EVLOOP_ONCE);//如果没有别的事件触发，就会被ev_loop触发退出
	} else if(milisecond < 0){
		event_base_loop(base, EVLOOP_ONCE);//触发一次就会退出，等待时间无限
	} else {
		event_base_loop(base, EVLOOP_ONCE | EVLOOP_NONBLOCK);//没有事件就会立即退出
	}
	return 0;
}

struct event_base *reactorCreate(void)
{
	return event_base_new();
}

int reactorLoop(struct event_base *base)
{
	event_base_dispatch(base);
	return 0;
}

void _canWrite(int fd, short what, void *arg);
int reactorWrite(reactor_fd_t rfd)
{
	struct event *evWrite;
	struct timeval timeout;
	evWrite = event_new(rfd->base, rfd->fd, EV_WRITE,_canWrite,rfd);
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	event_add(evWrite,&timeout );//&timeout//只要是可写的，write触发了的，就是正常连接
	rfd->evWrite = evWrite;
	return 0 ;
}
reactor_fd_t reactorListen(struct event_base *base, int port, bio_handler app, void *arg)
{  
	struct  sockaddr_in serverAddr;
    int serverFd;
	int ret=0;
    if((serverFd=socket(AF_INET,SOCK_STREAM,0))<0)
    {
       exit(-1);
    }
    
    serverAddr.sin_family=AF_INET;
    serverAddr.sin_port=htons(port);
    serverAddr.sin_addr.s_addr=htonl(INADDR_ANY);
 
    if((bind(serverFd,(struct sockaddr*)&serverAddr,sizeof(serverAddr))<0))
    {
        perror("bind failed");
		exit(-1);
    }
 
    if((ret=listen(serverFd,50))<0)
    {
        perror("listen failed");
        exit(-1);
    }
	
	return setfd(base,serverFd,type_LISTEN,app,arg);
}

reactor_fd_t reactorConnect(struct event_base *base, char *ip,int port, bio_handler app, void *arg)
{
    int fd;
    int ret;
	int flags;
    reactor_fd_t rfd;
    struct sockaddr_storage sa;
	
	
    memset(&sa, 0, sizeof(sa));
	
    if( port <= 0 || ip == NULL) return NULL;
	
	if(j_inet_pton(ip, &sa)<=0) {
		return NULL;
	}
	if(!sa.ss_family) sa.ss_family = AF_INET;
   
    if((fd = socket(AF_INET,SOCK_STREAM,0)) < 0) return NULL;

    flags = fcntl(fd, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(fd, F_SETFL, flags);
	
	j_inet_setport(&sa, port);
	
	
	

    ret = connect(fd,(struct sockaddr*)&sa,j_inet_addrlen(&sa));
    if(ret == 0)
    {
        debug("ACT:already ok?");
		rfd = setfd(base,fd,type_NORMAL,app,arg);
        if(rfd != NULL) return rfd;
    }
	debug("ACT:errno[%d]\r\n",errno);
	if(ret == -1 && (REACTOR_InProgress || REACTOR_WOULDBLOCK))
    {
        debug("ACT:need check\r\n");
		rfd = setfd(base,fd,type_CONNECT,app,arg);;
        if(rfd != NULL)
        {
            return rfd;
        }
    }
	close(fd);
    return NULL;
}
int reactorLoopBreak(struct event_base *base)
{
	event_base_loopbreak(base);
	return 0;
}

int reactorClose(reactor_fd_t rfd)
{
	debug("ACT: closed\n\r");
	removefd(rfd);
	if (rfd->bio_call != NULL)
        BIO(rfd, action_CLOSE, rfd->arg);
    close(rfd->fd);
	
    rfd->type = type_CLOSED;
	rfd->evRead=NULL;
	rfd->evWrite=NULL;
	rfd->base=NULL;
	rfd->bio_call = NULL;
	rfd->arg = NULL;
	free(rfd);
	return 0;
}

reactorTimer_t reactorTimerCreate(struct event_base *base,timer_handler app,void *arg) 
{
	reactorTimer_t reactorTimer = calloc(1,sizeof(struct reactorTimer_st));
	reactorTimer->base = base;
	reactorTimer->timer_call = app;
	reactorTimer->arg = arg;
	reactorTimer->evTimer = event_new(base, -1, 0, _event_timeout, reactorTimer);
	
	return reactorTimer;
}
int reactorTimerAdd(reactorTimer_t reactorTimer,int milisecond)
{
	struct timeval tv = {0};
	if(milisecond > 1000){
		tv.tv_sec = milisecond / 1000;
		milisecond %= 1000;
	}
	tv.tv_usec = milisecond * 1000;
	event_add(reactorTimer->evTimer, &tv);
	return 0;
}

int reactorTimerUpdate(reactorTimer_t reactorTimer,int milisecond)
{
	struct timeval tv = {0};
	if(milisecond > 1000){
		tv.tv_sec = milisecond / 1000;
		milisecond %= 1000;
	}
	tv.tv_usec = milisecond * 1000;
	event_del(reactorTimer->evTimer);
	return event_add(reactorTimer->evTimer, &tv);
	//可以直接使用event_add来更新时间。使用del可以强制不执行回调函数(当刚被激活时)
}

int reactorTimerDel(reactorTimer_t reactorTimer) 
{
	event_del(reactorTimer->evTimer);
	return 0;
}
int reactorTimerFree(reactorTimer_t reactorTimer) 
{
	event_free(reactorTimer->evTimer);
	free(reactorTimer);
	return 0;
}

void _event_timeout(evutil_socket_t fd, short flag, void *arg)
{
	reactorTimer_t timer = (reactorTimer_t)arg;
	timer->timer_call( timer, timer->arg);
}


void _canRead(int fd, short what, void *arg)
{
	reactor_fd_t rfd = (reactor_fd_t)arg;
	if(rfd->type == type_CLOSED)
		return;

    /* new conns on a listen socket */
    if(rfd->type == type_LISTEN)
    {
		debug("ACT:new conn\n\r");
    	processAccept(rfd);
        return;
    }
    /* read from ready sockets */
    if(rfd->type == type_NORMAL)
    {
		debug("ACT:get read\n\r");
		BIO(rfd,action_READ,rfd->arg);
		return;
    }
}

void _canWrite(int fd, short what, void *arg)
{
	reactor_fd_t rfd = (reactor_fd_t)arg;
	
	if(what&EV_TIMEOUT)  {
		debug("ACT:write time out\n\r");
		reactorClose(rfd);
		return;
	}
	
	if(rfd->type == type_CLOSED)
		return;

    /* new conns on a listen socket */
    if(rfd->type == type_CONNECT)
    {
		debug("ACT:check if connected\n\r");
    	if(0 == BIO(rfd,action_CONNECT,rfd->arg))
			rfd->type = type_NORMAL;
		else reactorClose(rfd);
        return;
    }
    /* read from ready sockets */
    if(rfd->type == type_NORMAL)
    {
		debug("ACT:normal write \n\r");
		if(-1 == BIO(rfd,action_WRITE,rfd->arg)) reactorClose(rfd);
		return;
    }
}

int processAccept(reactor_fd_t rfd)
{
	reactor_fd_t newRFD;
	struct sockaddr_in serv_addr;
    socklen_t addrlen = sizeof(serv_addr);
    int newfd;
   
    /* pull a socket off the accept queue and check */
    newfd =accept(rfd->fd, (struct sockaddr*)&serv_addr, &addrlen);
	newRFD = setfd(rfd->base,newfd,type_NORMAL,rfd->bio_call,rfd->arg);
	BIO(newRFD,action_ACCEPT,rfd->arg);//需要把serverFD提供的arg换掉
	return 0;
}

reactor_fd_t setfd(struct event_base *base,int sock,reactor_fd_type type,bio_handler app, void *arg)
{
	int flags;
	struct event *evRead;
	struct event *evWrite;
	struct timeval timeout;
	
	reactor_fd_t rfd = (reactor_fd_t)calloc(1,sizeof(struct reactor_fd_st ));
	rfd->base = base;
	
	rfd->fd = sock;
	rfd->type = type;

	evRead = event_new(rfd->base, rfd->fd, EV_READ|EV_PERSIST,_canRead,rfd);
	event_add(evRead, NULL);
	rfd->evRead = evRead;
	
	
	if(	type != type_LISTEN){
		evWrite = event_new(rfd->base, rfd->fd, EV_WRITE,_canWrite,rfd);
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;
		flags = event_add(evWrite,&timeout );//&timeout//只要是可写的，write触发了的，就是正常连接
		rfd->evWrite = evWrite;
	}	
	/* set the socket to non-blocking */
	rfd->bio_call = app;
	rfd->arg = arg;
	
    flags = fcntl(rfd->fd, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(rfd->fd, F_SETFL, flags);
	return rfd;
}

int removefd(reactor_fd_t rfd)
{
	if(rfd == NULL) return 0;
	if(rfd->evRead)
		event_del(rfd->evRead);
	if(rfd->evWrite)
		event_del(rfd->evWrite);
	return 0;
}



