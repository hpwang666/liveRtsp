
#ifndef _WEBSOCKET_COMMON_H_
#define _WEBSOCKET_COMMON_H_

#include <stdbool.h>

// #define WEBSOCKET_DEBUG

// websocket根据data[0]判别数据包类型    比如0x81 = 0x80 | 0x1 为一个txt类型数据包
typedef enum{
    WDT_MINDATA = 0x20,      // 0x0：标识一个中间数据包
    WDT_TXTDATA = 0x21,      // 0x1：标识一个txt类型数据包
    WDT_BINDATA= 0x22,      // 0x2：标识一个bin类型数据包
    WDT_DISCONN= 0x23,      // 0x8：标识一个断开连接类型数据包
    WDT_PING = 0x24,     // 0x8：标识一个断开连接类型数据包
    WDT_PONG = 0x25,     // 0xA：表示一个pong类型数据包
    WDT_ERR = 0x26,
	WDT_MISSING= 0x27,  //数据包还有后续部分
    WDT_NULL = 0
}WS_DATA_TYPE;


WS_DATA_TYPE ws_dePackage( char *data,  int dataLen,  char *package,  int *packageLen);
int webSocket_clientLinkToServer(char *ip, int port, char *interface_path);
int ws_serverRespToClient(char *recvBuf,char *respBuf);
int ws_buildRespondShakeKey( char *acceptKey,  int acceptKeyLen,  char *respondKey);
int ws_genChannel(char *ip,int port,char *channel);
int ws_genWspChannnel(char *src,char *channel,int);
int ws_genWspOK(char *resp,char *channel,int seq);
int ws_genRtp( char *resp,  char *content,int dataLen, WS_DATA_TYPE type);
int ws_genWspResp(char *resp,char *content,int len,int seq, WS_DATA_TYPE type);
void webSocket_delayms(unsigned int ms);



#endif

