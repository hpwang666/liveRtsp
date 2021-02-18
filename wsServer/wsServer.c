
#include <stdio.h>
#include <stdlib.h>

#include "bio.h"
#include "reactor.h"
#include "bio_buf.h"
#include "websocket_common.h"


int server_handler(bioConn_t c, bio_event_t ev, void *arg)
{
	switch(ev){
	case bio_READ:
		//printf("got %d bytes \r\n",bioBuf->len);
		return 0;
	case bio_CLOSED:
		printf("APP:closed,client=%s:%d\n", c->peer_ip,c->peer_port);
		return 0;
	case bio_CONNECTED:
		printf("APP:Connected,client=%s:%d\n", c->peer_ip,c->peer_port);
		return 0;
	default:
		return 0;
	}
	return 0;
}

int main()
{
	int port = 9004;
	struct event_base * r =reactorCreate();
	bioConn_t conn = wsServerCreate(r,port, server_handler, NULL);
	reactorLoop(r);
	free(conn);
	return 0;
}
