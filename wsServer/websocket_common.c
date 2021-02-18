
#include "websocket_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>     // 使用 malloc, calloc等动态分配内存方法
#include <time.h>       // 获取系统时间
#include <errno.h>
#include <fcntl.h>      // 非阻塞
#include <sys/un.h> 
#include <arpa/inet.h>  // inet_addr()
#include <unistd.h>     // close()
#include <sys/types.h>  // 文件IO操作
#include <sys/socket.h> //
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>      // gethostbyname, gethostbyname2, gethostbyname_r, gethostbyname_r2
#include <sys/un.h> 
#include <sys/time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>  // SIOCSIFADDR

//==============================================================================================
//======================================== 设置和工具部分 =======================================
//==============================================================================================



//==================== 加密方法BASE64 ====================

//base64编/解码用的基础字符集
const char websocket_base64char[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*******************************************************************************
 * 名称: websocket_base64_encode
 * 功能: ascii编码为base64格式
 * 形参: bindata : ascii字符串输入
 *            base64 : base64字符串输出
 *          binlength : bindata的长度
 * 返回: base64字符串长度
 * 说明: 无
 ******************************************************************************/
int websocket_base64_encode( const unsigned char *bindata, char *base64, int binlength)
{
    int i, j;
    unsigned char current;
    for ( i = 0, j = 0 ; i < binlength ; i += 3 )
    {
        current = (bindata[i] >> 2) ;
        current &= (unsigned char)0x3F;
        base64[j++] = websocket_base64char[(int)current];
        current = ( (unsigned char)(bindata[i] << 4 ) ) & ( (unsigned char)0x30 ) ;
        if ( i + 1 >= binlength )
        {
            base64[j++] = websocket_base64char[(int)current];
            base64[j++] = '=';
            base64[j++] = '=';
            break;
        }
        current |= ( (unsigned char)(bindata[i+1] >> 4) ) & ( (unsigned char) 0x0F );
        base64[j++] = websocket_base64char[(int)current];
        current = ( (unsigned char)(bindata[i+1] << 2) ) & ( (unsigned char)0x3C ) ;
        if ( i + 2 >= binlength )
        {
            base64[j++] = websocket_base64char[(int)current];
            base64[j++] = '=';
            break;
        }
        current |= ( (unsigned char)(bindata[i+2] >> 6) ) & ( (unsigned char) 0x03 );
        base64[j++] = websocket_base64char[(int)current];
        current = ( (unsigned char)bindata[i+2] ) & ( (unsigned char)0x3F ) ;
        base64[j++] = websocket_base64char[(int)current];
    }
    base64[j] = '\0';
    return j;
}
/*******************************************************************************
 * 名称: websocket_base64_decode
 * 功能: base64格式解码为ascii
 * 形参: base64 : base64字符串输入
 *            bindata : ascii字符串输出
 * 返回: 解码出来的ascii字符串长度
 * 说明: 无
 ******************************************************************************/
int websocket_base64_decode( const char *base64, unsigned char *bindata)
{
    int i, j;
    unsigned char k;
    unsigned char temp[4];
    for ( i = 0, j = 0; base64[i] != '\0' ; i += 4 )
    {
        memset( temp, 0xFF, sizeof(temp) );
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( websocket_base64char[k] == base64[i] )
                temp[0]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( websocket_base64char[k] == base64[i+1] )
                temp[1]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( websocket_base64char[k] == base64[i+2] )
                temp[2]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( websocket_base64char[k] == base64[i+3] )
                temp[3]= k;
        }
        bindata[j++] = ((unsigned char)(((unsigned char)(temp[0] << 2))&0xFC)) | \
                ((unsigned char)((unsigned char)(temp[1]>>4)&0x03));
        if ( base64[i+2] == '=' )
            break;
        bindata[j++] = ((unsigned char)(((unsigned char)(temp[1] << 4))&0xF0)) | \
                ((unsigned char)((unsigned char)(temp[2]>>2)&0x0F));
        if ( base64[i+3] == '=' )
            break;
        bindata[j++] = ((unsigned char)(((unsigned char)(temp[2] << 6))&0xF0)) | \
                ((unsigned char)(temp[3]&0x3F));
    }
    return j;
}

//==================== 加密方法 sha1哈希 ====================

typedef struct SHA1Context{  
    unsigned Message_Digest[5];        
    unsigned Length_Low;               
    unsigned Length_High;              
    unsigned char Message_Block[64];   
    int Message_Block_Index;           
    int Computed;                      
    int Corrupted;                     
} SHA1Context;  

#define SHA1CircularShift(bits,word) ((((word) << (bits)) & 0xFFFFFFFF) | ((word) >> (32-(bits))))  

void SHA1ProcessMessageBlock(SHA1Context *context)
{  
    const unsigned K[] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 };  
    int         t;                  
    unsigned    temp;               
    unsigned    W[80];              
    unsigned    A, B, C, D, E;      
  
    for(t = 0; t < 16; t++) 
    {  
        W[t] = ((unsigned) context->Message_Block[t * 4]) << 24;  
        W[t] |= ((unsigned) context->Message_Block[t * 4 + 1]) << 16;  
        W[t] |= ((unsigned) context->Message_Block[t * 4 + 2]) << 8;  
        W[t] |= ((unsigned) context->Message_Block[t * 4 + 3]);  
    }  
      
    for(t = 16; t < 80; t++)  
        W[t] = SHA1CircularShift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);  
  
    A = context->Message_Digest[0];  
    B = context->Message_Digest[1];  
    C = context->Message_Digest[2];  
    D = context->Message_Digest[3];  
    E = context->Message_Digest[4];  
  
    for(t = 0; t < 20; t++) 
    {  
        temp =  SHA1CircularShift(5,A) + ((B & C) | ((~B) & D)) + E + W[t] + K[0];  
        temp &= 0xFFFFFFFF;  
        E = D;  
        D = C;  
        C = SHA1CircularShift(30,B);  
        B = A;  
        A = temp;  
    }  
    for(t = 20; t < 40; t++) 
    {  
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[1];  
        temp &= 0xFFFFFFFF;  
        E = D;  
        D = C;  
        C = SHA1CircularShift(30,B);  
        B = A;  
        A = temp;  
    }  
    for(t = 40; t < 60; t++) 
    {  
        temp = SHA1CircularShift(5,A) + ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];  
        temp &= 0xFFFFFFFF;  
        E = D;  
        D = C;  
        C = SHA1CircularShift(30,B);  
        B = A;  
        A = temp;  
    }  
    for(t = 60; t < 80; t++) 
    {  
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[3];  
        temp &= 0xFFFFFFFF;  
        E = D;  
        D = C;  
        C = SHA1CircularShift(30,B);  
        B = A;  
        A = temp;  
    }  
    context->Message_Digest[0] = (context->Message_Digest[0] + A) & 0xFFFFFFFF;  
    context->Message_Digest[1] = (context->Message_Digest[1] + B) & 0xFFFFFFFF;  
    context->Message_Digest[2] = (context->Message_Digest[2] + C) & 0xFFFFFFFF;  
    context->Message_Digest[3] = (context->Message_Digest[3] + D) & 0xFFFFFFFF;  
    context->Message_Digest[4] = (context->Message_Digest[4] + E) & 0xFFFFFFFF;  
    context->Message_Block_Index = 0;  
} 

void SHA1Reset(SHA1Context *context)
{
    context->Length_Low             = 0;  
    context->Length_High            = 0;  
    context->Message_Block_Index    = 0;  
  
    context->Message_Digest[0]      = 0x67452301;  
    context->Message_Digest[1]      = 0xEFCDAB89;  
    context->Message_Digest[2]      = 0x98BADCFE;  
    context->Message_Digest[3]      = 0x10325476;  
    context->Message_Digest[4]      = 0xC3D2E1F0;  
  
    context->Computed   = 0;  
    context->Corrupted  = 0;  
}  
  
void SHA1PadMessage(SHA1Context *context)
{  
    if (context->Message_Block_Index > 55) 
    {  
        context->Message_Block[context->Message_Block_Index++] = 0x80;  
        while(context->Message_Block_Index < 64)  context->Message_Block[context->Message_Block_Index++] = 0;  
        SHA1ProcessMessageBlock(context);  
        while(context->Message_Block_Index < 56) context->Message_Block[context->Message_Block_Index++] = 0;  
    } 
    else 
    {  
        context->Message_Block[context->Message_Block_Index++] = 0x80;  
        while(context->Message_Block_Index < 56) context->Message_Block[context->Message_Block_Index++] = 0;  
    }  
    context->Message_Block[56] = (context->Length_High >> 24 ) & 0xFF;  
    context->Message_Block[57] = (context->Length_High >> 16 ) & 0xFF;  
    context->Message_Block[58] = (context->Length_High >> 8 ) & 0xFF;  
    context->Message_Block[59] = (context->Length_High) & 0xFF;  
    context->Message_Block[60] = (context->Length_Low >> 24 ) & 0xFF;  
    context->Message_Block[61] = (context->Length_Low >> 16 ) & 0xFF;  
    context->Message_Block[62] = (context->Length_Low >> 8 ) & 0xFF;  
    context->Message_Block[63] = (context->Length_Low) & 0xFF;  
  
    SHA1ProcessMessageBlock(context);  
} 

int SHA1Result(SHA1Context *context)
{
    if (context->Corrupted) 
    {  
        return 0;  
    }  
    if (!context->Computed) 
    {  
        SHA1PadMessage(context);  
        context->Computed = 1;  
    }  
    return 1;  
}  
  
  
void SHA1Input(SHA1Context *context,const char *message_array,unsigned length){  
    if (!length) 
        return;  
  
    if (context->Computed || context->Corrupted)
    {  
        context->Corrupted = 1;  
        return;  
    }  
  
    while(length-- && !context->Corrupted)
    {  
        context->Message_Block[context->Message_Block_Index++] = (*message_array & 0xFF);  
  
        context->Length_Low += 8;  
  
        context->Length_Low &= 0xFFFFFFFF;  
        if (context->Length_Low == 0)
        {  
            context->Length_High++;  
            context->Length_High &= 0xFFFFFFFF;  
            if (context->Length_High == 0) context->Corrupted = 1;  
        }  
  
        if (context->Message_Block_Index == 64)
        {  
            SHA1ProcessMessageBlock(context);  
        }  
        message_array++;  
    }  
}

  
char * sha1_hash(const char *source){   // Main  
    SHA1Context sha;  
    char *buf;//[128];  
  
    SHA1Reset(&sha);  
    SHA1Input(&sha, source, strlen(source));  
  
    if (!SHA1Result(&sha))
    {  
        printf("SHA1 ERROR: Could not compute message digest");  
        return NULL;  
    } 
    else 
    {  
        buf = (char *)malloc(128);  
        memset(buf, 0, 128);  
        sprintf(buf, "%08X%08X%08X%08X%08X", sha.Message_Digest[0],sha.Message_Digest[1],  
        sha.Message_Digest[2],sha.Message_Digest[3],sha.Message_Digest[4]);  
        //lr_save_string(buf, lrvar);  
          
        //return strlen(buf);  
        return buf;  
    }  
}  

int tolower(int c)   
{   
    if (c >= 'A' && c <= 'Z')   
    {   
        return c + 'a' - 'A';   
    }   
    else   
    {   
        return c;   
    }   
}

int htoi(const char s[], int start, int len)   
{   
    int i, j;   
    int n = 0;   
    if (s[0] == '0' && (s[1]=='x' || s[1]=='X')) //判断是否有前导0x或者0X  
    {   
        i = 2;   
    }   
    else   
    {   
        i = 0;   
    }   
    i+=start;  
    j=0;  
    for (; (s[i] >= '0' && s[i] <= '9')   
       || (s[i] >= 'a' && s[i] <= 'f') || (s[i] >='A' && s[i] <= 'F');++i)   
    {     
        if(j>=len)  
        {  
            break;  
        }  
        if (tolower(s[i]) > '9')   
        {   
            n = 16 * n + (10 + tolower(s[i]) - 'a');   
        }   
        else   
        {   
            n = 16 * n + (tolower(s[i]) - '0');   
        }   
        j++;  
    }   
    return n;   
}   


int ws_buildRespondShakeKey( char *acceptKey,  int acceptKeyLen,  char *respondKey)
{
    char *clientKey;  
    char *sha1DataTemp;  
    char *sha1Data;  
    int i, n;  
    char GUID[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";  
    int GUIDLEN;
    
    if(acceptKey == NULL)  
        return 0;  
    GUIDLEN = sizeof(GUID);
    clientKey = (char *)calloc(acceptKeyLen + GUIDLEN + 10, sizeof(char));  
    memset(clientKey, 0, (acceptKeyLen + GUIDLEN + 10));
    //
    memcpy(clientKey, acceptKey, acceptKeyLen); 
    memcpy(&clientKey[acceptKeyLen], GUID, GUIDLEN);
    clientKey[acceptKeyLen + GUIDLEN] = '\0';
    //
    sha1DataTemp = sha1_hash(clientKey);  
    n = strlen((const char *)sha1DataTemp);  
    sha1Data = (char *)calloc(n / 2 + 1, sizeof(char));  
    memset(sha1Data, 0, n / 2 + 1);  
   //
    for(i = 0; i < n; i += 2)  
        sha1Data[ i / 2 ] = htoi(sha1DataTemp, i, 2);      
    n = websocket_base64_encode((const unsigned char *)sha1Data, (char *)respondKey, (n / 2));
    //
    free(sha1DataTemp);
    free(sha1Data);
    free(clientKey);
    return n;
}

void webSocket_getRandomString(unsigned char *buf, unsigned int len)
{
    unsigned int i;
    unsigned char temp;
    srand((int)time(0));
    for(i = 0; i < len; i++)
    {
        temp = (unsigned char)(rand()%256);
        if(temp == 0)   // 随机数不要0, 0 会干扰对字符串长度的判断
            temp = 128;
        buf[i] = temp;
    }
}

int ws_genRtp( char *resp,  char *content,int dataLen, WS_DATA_TYPE type)
{
	int pkgLen;
	char *dataHead = NULL;
    
    
    if(type == WDT_MINDATA)
        *resp = 0x00;
    else if(type == WDT_TXTDATA)
        *resp = 0x81;
    else if(type == WDT_BINDATA)
        *resp = 0x82;
    else if(type == WDT_DISCONN)
        *resp = 0x88;
    else if(type == WDT_PING)
        *resp = 0x89;
    else if(type == WDT_PONG)
        *resp = 0x8A;
    else
        return -1;
    
    
    //
    if(dataLen < 126)
    {
        *(resp+1) = (dataLen&0x7F);
        pkgLen =dataLen+2;
		dataHead = resp+2;
    }
    else if(dataLen < 65536)
    {
		*(resp+1) = 0x7E;
		*(resp+2) = ((dataLen >> 8) & 0xFF);
		*(resp+3) = dataLen & 0x000000FF;
        pkgLen =dataLen+4;
		dataHead = resp+4;
    }
    else if(dataLen < 0xFFFFFFFF)
    {
        *resp++ |= 0x7F;
        *resp++ = 0; //(char)((dataLen >> 56) & 0xFF);   // 数据长度变量是 unsigned int dataLen, 暂时没有那么多数据
        *resp++ = 0; //(char)((dataLen >> 48) & 0xFF);
        *resp++ = 0; //(char)((dataLen >> 40) & 0xFF);
        *resp++ = 0; //(char)((dataLen >> 32) & 0xFF);
        *resp++ = (char)((dataLen >> 24) & 0xFF);        // 到这里就够传4GB数据了
        *resp++ = (char)((dataLen >> 16) & 0xFF);
        *resp++ = (char)((dataLen >> 8) & 0xFF);
        *resp++ = (char)((dataLen >> 0) & 0xFF);
        
    }

    
        memcpy(dataHead, content, dataLen);
    
    
    //
    return pkgLen;
}


//生成回传数据包，确认连接
//WSP/1.1 200 OK
//seq:1
//

int ws_genWspOK(char *resp,char *channel,int seq)
{
	int len;
	char wspDemo[128] = "WSP/1.1 200 OK\r\n"
                        "seq: ";
                        
                      
	sprintf(wspDemo+strlen(wspDemo),"%d\r\n",seq);
	if(channel){
		sprintf(wspDemo+strlen(wspDemo),"channel:%s\r\n",channel);
	}
	strcat(wspDemo,"\r\n");
	len= strlen(wspDemo);
	*resp= 0x81;
	*(resp+1) =  len;
	memcpy(resp+2,wspDemo,len);
	return len+2;
}


int ws_genWspResp(char *resp,char *content,int contentLen,int seq, WS_DATA_TYPE type)
{
	int len,pkgLen;
	char *dataHead = NULL;
	char wspDemo[64] = "WSP/1.1 200 OK\r\n"
                        "seq: ";
                        
    //char dd[]={0x81,0x7e,0x00,0xb3,0x57,0x53,0x50,0x2f,0x31,0x2e,0x31,0x20,0x32,0x30,0x30,0x20,0x4f,0x4b,0x0d,0x0a,0x73,0x65,0x71,0x3a,0x20,0x33,0x0d,0x0a,0x0d,0x0a,0x52,0x54,0x53,0x50,0x2f,0x31,0x2e,0x30,0x20,0x32,0x30,0x30,0x20,0x4f,0x4b,0x0d,0x0a,0x43,0x53,0x65,0x71,0x3a,0x20,0x31,0x0d,0x0a,0x50,0x75,0x62,0x6c,0x69,0x63,0x3a,0x20,0x4f,0x50,0x54,0x49,0x4f,0x4e,0x53,0x2c,0x20,0x44,0x45,0x53,0x43,0x52,0x49,0x42,0x45,0x2c,0x20,0x50,0x4c,0x41,0x59,0x2c,0x20,0x50,0x41,0x55,0x53,0x45,0x2c,0x20,0x53,0x45,0x54,0x55,0x50,0x2c,0x20,0x54,0x45,0x41,0x52,0x44,0x4f,0x57,0x4e,0x2c,0x20,0x53,0x45,0x54,0x5f,0x50,0x41,0x52,0x41,0x4d,0x45,0x54,0x45,0x52,0x2c,0x20,0x47,0x45,0x54,0x5f,0x50,0x41,0x52,0x41,0x4d,0x45,0x54,0x45,0x52,0x0d,0x0a,0x44,0x61,0x74,0x65,0x3a,0x20,0x20,0x4d,0x6f,0x6e,0x2c,0x20,0x41,0x70,0x72,0x20,0x31,0x35,0x20,0x32,0x30,0x31,0x39,0x20,0x31,0x35,0x3a,0x33,0x36,0x3a,0x32,0x39,0x20,0x47,0x4d,0x54,0x0d,0x0a,0x0d,0x0a};                  
	sprintf(wspDemo+strlen(wspDemo),"%d\r\n\r\n",seq);
	
	if(type == WDT_MINDATA)
        *resp = 0x00;
    else if(type == WDT_TXTDATA)
        *resp = 0x81;
    else if(type == WDT_BINDATA)
        *resp = 0x82;
    else if(type == WDT_DISCONN)
        *resp = 0x88;
    else if(type == WDT_PING)
        *resp = 0x89;
    else if(type == WDT_PONG)
        *resp = 0x8A;
    else
        return -1;
		
	len = strlen(wspDemo)+contentLen;	
		
	if((len) < 126)
    {
        *(resp+1) = (len&0x7F);//no mask
		dataHead = resp+2;
		pkgLen = len+2;
    }
    else if(len < 65536)
    {
		*(resp+1) = 0x7E;
		*(resp+2) = ((len >> 8) & 0xFF);
		*(resp+3) = len & 0x000000FF;
		dataHead = resp+4;
		pkgLen = len+4;
    }
	
	memcpy(dataHead,wspDemo,strlen(wspDemo));
	dataHead+=strlen(wspDemo);
	memcpy(dataHead,content,contentLen);

	//memcpy(resp,dd,183);
	return pkgLen;
}


//产生通道session
int ws_genChannel(char *ip,int port,char *channel)
{
	char ch[128];
	
	char *c = NULL;
	memcpy(ch,ip,strlen(ip));
	sprintf(ch+strlen(ip),"%d",port);
	c = sha1_hash(ch);
	memcpy(channel,c,strlen(c));
	free(c);
	return 0;
}


/*******************************************************************************
 * 功能: websocket数据收发阶段的数据解包, 通常client发server的数据都要isMask(掩码)处理, 反之server到client却不用
 * 形参: *data：解包的数据
 *      dataLen : 长度
 *      *package : 解包后存储地址

 *      *packageLen : 解包所得长度
 * 返回: 解包识别的数据类型 如 : txt数据, bin数据, ping, pong等
 * 说明: 无
 ******************************************************************************/
WS_DATA_TYPE ws_dePackage( char *data,  int dataLen,  char *package,  int *packageLen)
{
    unsigned char maskKey[4] = {0};    // 掩码
    unsigned char temp1, temp2;
    char Mask = 0, type;
    int count;
	WS_DATA_TYPE ret;
    int i, len = 0, dataStart = 2;
    if(dataLen < 2)
        return WDT_ERR;
    
    type = data[0]&0x0F;
    if((data[0]&0x80) == 0x80) //所有数据包都应是0x80开头
    {
        if(type == 0x01) 
            ret = WDT_TXTDATA;
        else if(type == 0x02) 
            ret = WDT_BINDATA;
        else if(type == 0x08) 
            ret = WDT_DISCONN;
        else if(type == 0x09) 
            ret = WDT_PING;
        else if(type == 0x0A) 
            ret = WDT_PONG;
        else 
            return WDT_ERR;
    }
    else {//被TCP拆包的包，或则是握手开头
		memset(package,'\0',4096);
		memcpy(package,data,dataLen);
		*packageLen = dataLen;
		return WDT_MINDATA;
	}
	  
    if((data[1] & 0x80) == 0x80)//使用掩码
    {
        Mask = 1;
        count = 4;
    }
    else
    {
        Mask = 0;
        count = 0;
    }
    //
    len = data[1] & 0x7F;
    if(len == 126) //此时第二字节不表示数据长度，紧跟着的两位表示数据长度
    {
        len = 0xff&data[2];
        len = (len << 8)|(0xff&data[3]);
        if(packageLen) *packageLen = len;//转储包长度
        if(dataLen < len + 4 + count)
            return WDT_MISSING;//数据未完
        if(Mask)
        {
            maskKey[0] = data[4];
            maskKey[1] = data[5];
            maskKey[2] = data[6];
            maskKey[3] = data[7];
            dataStart = 8;
        }
        else
            dataStart = 4;
    }
    else if(len == 127)//此时第二字节不表示数据长度，紧跟着的8位表示数据长度
    {
        if(data[2] != 0 || data[3] != 0 || data[4] != 0 || data[5] != 0)    //使用8个字节存储长度时,前4位必须为0,装不下那么多数据...
            return WDT_ERR;
        len = data[6];
        len = (len << 8) + data[7];
        len = (len << 8) + data[8];
        len = (len << 8) + data[9];
        if(packageLen) *packageLen = len;//转储包长度
        
        if(dataLen < len + 10 + count)
            return WDT_MISSING;
        if(Mask)
        {
            maskKey[0] = data[10];
            maskKey[1] = data[11];
            maskKey[2] = data[12];
            maskKey[3] = data[13];
            dataStart = 14;
        }
        else
            dataStart = 10;
    }
    else//数据长度小于126
    {
        if(packageLen) *packageLen = len;//转储包长度
        //
        if(dataLen < len + 2 + count)
            return WDT_MISSING;
        if(Mask)
        {
            maskKey[0] = data[2];
            maskKey[1] = data[3];
            maskKey[2] = data[4];
            maskKey[3] = data[5];
            dataStart = 6;
        }
        else
            dataStart = 2;
    }
   
    if(Mask)    // 解包数据使用掩码时, 使用异或解码, maskKey[4]依次和数据异或运算, 逻辑如下
    {
        for(i = 0, count = 0; i < len; i++)
        {
            temp1 = maskKey[count];
            temp2 = data[i + dataStart];
            *package++ =  (char)(((~temp1)&temp2) | (temp1&(~temp2)));  // 异或运算后得到数据
            count += 1;
            if(count >= sizeof(maskKey))    // maskKey[4]循环使用
                count = 0;
        }
        *package = '\0';
    }
    else    // 解包数据没使用掩码, 直接复制数据段
    {
        memcpy(package, &data[dataStart], len);
        package[len] = '\0';
    }
    //
    return ret;
}


/*******************************************************************************
 * 名称: webSocket_serverLinkToClient
 * 功能: 服务器回复客户端的连接请求, 以建立websocket连接
 * 形参: fd：连接句柄
 *      *recvBuf : 接收到来自客户端的数据(内含http连接请求)
 *      bufLen : 
 * 返回: =0 建立websocket连接成功 <0 建立websocket连接失败
 * 说明: 无
 ******************************************************************************/
int ws_serverRespToClient(char *recvBuf,char *respBuf)
{
    char *p=NULL;
    int len;
    char recvShakeKey[512], recvProtcol[128],timeStr[256];
	
	time_t now;
    struct tm *tm_now;
    char respondShakeKey[256] = {0};
	
	char httpDemo[] = 	"HTTP/1.1 101 Switching Protocols\r\n"
                        "Upgrade: websocket\r\n"
                        "Server: Microsoft-HTTPAPI/2.0\r\n"
                        "Connection: Upgrade\r\n";
                        //
                        //"%s\r\n\r\n";  // 时间打包待续        // 格式如 "Date: Tue, 20 Jun 2017 08:50:41 CST\r\n"
						
						
						
   
	memset(respBuf,'\0',4096);
    sprintf(respBuf, "%s",httpDemo);
	len = strlen(respBuf);
	
	// 构建回应的握手key
	if((p = strstr(recvBuf, "Sec-WebSocket-Key: ")) == NULL)
        return -1;
    p += strlen("Sec-WebSocket-Key: ");
    memset(recvShakeKey, '\0', sizeof(recvShakeKey));
	memset(respondShakeKey, '\0', sizeof(respondShakeKey));
    sscanf(p, "%s", recvShakeKey);      // 取得握手key
    ws_buildRespondShakeKey(recvShakeKey, strlen(recvShakeKey), respondShakeKey); 
	
	sprintf(respBuf+len, "Sec-WebSocket-Accept: %s\r\n",respondShakeKey);
	len = strlen(respBuf);
    
	
	p = strstr(recvBuf, "Sec-WebSocket-Protocol: ");//"Sec-WebSocket-Protocol: control\r\n"
	if(p){
		sscanf(p, "%s", recvProtcol);  
		p+=strlen(recvProtcol);
		sscanf(p, "%s", recvProtcol+strlen(recvProtcol)); 
		strcat(recvProtcol,"\r\n");
		sprintf(respBuf+len, "%s",recvProtcol);
		len = strlen(respBuf);
	}
	
    time(&now);
    tm_now = localtime(&now);
    strftime(timeStr, sizeof(timeStr), "Date: %a, %d %b %Y %T %Z", tm_now);
    // 组成回复信息
    sprintf(respBuf+len, "%s\r\n\r\n",timeStr);
	//
    return 0;
}

