#pragma hdrstop

#pragma checkoption -tWM

//---------------------------------------------------------------------------
#include <iostream>

#ifdef _WIN32
	#include <process.h>
	#include <windows.h>
	#include <io.h>
	#include <sys\stat.h>
#else
	/* POSIX-compatible includes */
	#include <assert.h>
	#include <sys/types.h>
	#include <sys/select.h>
	#include <sys/socket.h>
	#include <sys/stat.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
	
	#include <pthread.h>
	#include <signal.h>
	#include <sys/ioctl.h>
	#include <errno.h>
	#include <stdlib.h>
	#include <unistd.h>


	/* Простые переименования и дополненьица */
	#define O_BINARY 0
	#define ioctlsocket ioctl
	#define SOCKET int

	/*Максимальный размер стека потока */
	#if defined(__LP64__)
		#define THREAD_STACK_SIZE 65536 * 2
	#else
		#define THREAD_STACK_SIZE 65536
	#endif
#endif /* POSIX-compatible includes */

#ifdef DEBUG
#define DPRINTF(...) printf(__VA_ARGS__)
#else
#define DPRINTF(...)
#endif

#include <string.h>
#include <stdio.h>
#include <fcntl.h>

#include "icqkid2.h"
#include "revision.h"
#include "statgen.h"
#include "md5.h"

// Константы операций (взаимодействие с сервером шлюза)
#define T_REQLOGIN 1
#define T_SENDMSG 2
#define T_RECVMSG 3
#define T_LOGIN 4
#define T_ERROR 6
#define T_CLENTRY 7
#define T_STATUSCHANGE 9
#define T_AUTHREQ 10
#define T_REQINFOSHORT 11
#define T_ADDCONTACT 12
#define T_SSLRESP 13
#define T_AUTHGRANT 14
#define T_MY_STATUS_CH 15   // Изменение моего статуса
//Сервер (аол) получил сообщение
#define T_SRV_ACK 16
//Клиент получил сообщение
#define T_CLIENT_ACK 17

#define T_ECHO 18
#define T_ECHORET 19

#define T_GROUPID 20
#define T_GROUPFOLLOW 21

#define T_MY_XSTATUS_CH 22

//Мой ответ Чемберлену (подтверждение доставки)
#define T_MSGACK 23

#define T_XTEXT_REQ 24
#define T_XTEXT_ACK 25
#define T_XTEXT_SET 26

#define T_ADDCONTACT_WITH_GRP 27

#define T_ADDGROUP 28
#define T_ADDIGNORE 29
#define T_SETPRIVACY 30
#define T_LASTPRIVACY 31

#define T_SETCLIENT_ID 32

#define T_REMOVECONTACT 33
	/* Удаление контакта (client->server) */
#define T_CONTACTREMOVED 34
	/* Удаление контакта (server->client) */
#define T_MD5AUTH 35
#pragma pack(push)
#pragma pack(1)
typedef struct
{
        uint32_t uin;
        uint16_t type;
        uint16_t len;
        char data[16384];
}NatICQ_PKT;
#pragma pack(pop)

typedef struct
{
        uint32_t SEQ;
        uint32_t uin;
        char cookies[8];
}TACK;
						
/*****************************************************/
					  
class MyIcqInterface : public ICQKid2{
	virtual void getMD5hash(vector<uint8_t> md5_salt, uint8_t * md5_hash);
        virtual void onIncomingMsg(ICQKid2Message msg);
        virtual void onXstatusChanged(string uin, vector<uint8_t> x_status, string x_title, string x_descr);
		virtual void onClientMsgAck(string uin, uint8_t *cookie);
		virtual void onServerMsgAck(string uin, uint8_t *cookie);
		virtual void onUserNotify(string uin, uint32_t stat1, uint32_t stat2, bool invis_flag, vector<uint8_t> xs);
        virtual void onClientIDNotify(string uin, uint8_t clientid); 
        virtual void onSingOff(uint16_t err_code, string err_url);
        virtual void onAuthRequest(string from, string text);
        virtual void onAuthReply(string from, string text, uint8_t aflag);
public:
	int total_msg;
        int total_sended;
	int naticq_sock;
        int ack_size;
        TACK ack_cache[32];
        void NatICQTX(NatICQ_PKT *p);
	bool md5auth;
};

/* Нужные объекты синхронизации */
#define SYNC_NUM 2      /* Максимальное число объектов синхронизации */

#define CRIT_STAT 0     /* Статистика клиентов */
#ifdef _WIN32
CRITICAL_SECTION CritSection[SYNC_NUM];
#else
pthread_mutex_t mtx[SYNC_NUM];
#endif

int NatICQRX(int sock, NatICQ_PKT *p, int tmr);

inline void Mutex_Lock(unsigned short crit_index)
{
#ifdef _WIN32
    EnterCriticalSection(&CritSection[crit_index]);
#else
    pthread_mutex_lock(&mtx[crit_index]);
    
#endif
}
inline void Mutex_Unlock(unsigned short crit_index)
{
#ifdef _WIN32
    LeaveCriticalSection(&CritSection[crit_index]);
#else
    pthread_mutex_unlock(&mtx[crit_index]);
#endif
}

inline void Mutex_Init(unsigned short crit_index)
{
#ifdef _WIN32
	InitializeCriticalSection(&CritSection[crit_index]);
#else
	int rc;
	rc = pthread_mutex_init(&mtx[crit_index], NULL);
	assert(rc != -1);
#endif
}

inline void Mutex_Destroy(unsigned short crit_index)
{
#ifdef _WIN32
	DeleteCriticalSection(&CritSection[crit_index]);
#else
	pthread_mutex_destroy(&mtx[crit_index]);
#endif
}

unsigned short ClientsCount = 0;
char *StatOutput_Path = NULL;

#pragma hdrstop
unsigned int char16to8(unsigned int c)
{
  typedef struct
  {
   unsigned short u;
   unsigned char dos;
   unsigned char win;
   unsigned char koi8;
  } TUNICODE2CHAR;
  static const TUNICODE2CHAR unicode2char[]=
  {
  // CAPITAL Cyrillic letters (base)
  0x410,0x80,0xC0,0xE1, // А
  0x411,0x81,0xC1,0xE2, // Б
  0x412,0x82,0xC2,0xF7, // В
  0x413,0x83,0xC3,0xE7, // Г
  0x414,0x84,0xC4,0xE4, // Д
  0x415,0x85,0xC5,0xE5, // Е
  0x416,0x86,0xC6,0xF6, // Ж
  0x417,0x87,0xC7,0xFA, // З
  0x418,0x88,0xC8,0xE9, // И
  0x419,0x89,0xC9,0xEA, // Й
  0x41A,0x8A,0xCA,0xEB, // К
  0x41B,0x8B,0xCB,0xEC, // Л
  0x41C,0x8C,0xCC,0xED, // М
  0x41D,0x8D,0xCD,0xEE, // Н
  0x41E,0x8E,0xCE,0xEF, // О
  0x41F,0x8F,0xCF,0xF0, // П
  0x420,0x90,0xD0,0xF2, // Р
  0x421,0x91,0xD1,0xF3, // С
  0x422,0x92,0xD2,0xF4, // Т
  0x423,0x93,0xD3,0xF5, // У
  0x424,0x94,0xD4,0xE6, // Ф
  0x425,0x95,0xD5,0xE8, // Х
  0x426,0x96,0xD6,0xE3, // Ц
  0x427,0x97,0xD7,0xFE, // Ч
  0x428,0x98,0xD8,0xFB, // Ш
  0x429,0x99,0xD9,0xFD, // Щ
  0x42A,0x9A,0xDA,0xFF, // Ъ
  0x42B,0x9B,0xDB,0xF9, // Ы
  0x42C,0x9C,0xDC,0xF8, // Ь
  0x42D,0x9D,0xDD,0xFC, // Э
  0x42E,0x9E,0xDE,0xE0, // Ю
  0x42F,0x9F,0xDF,0xF1, // Я
  // CAPITAL Cyrillic letters (additional)
  0x402,'_',0x80,'_', // _ .*.*
  0x403,'_',0x81,'_', // _ .*.*
  0x409,'_',0x8A,'_', // _ .*.*
  0x40A,'_',0x8C,'_', // _ .*.*
  0x40C,'_',0x8D,'_', // _ .*.*
  0x40B,'_',0x8E,'_', // _ .*.*
  0x40F,'_',0x8F,'_', // _ .*.*
  0x40E,0xF6,0xA1,'_', // Ў ...*
  0x408,0x4A,0xA3,0x4A, // _ .*.*
  0x409,0x83,0xA5,0xBD, // _ .*..
  0x401,0xF0,0xA8,0xB3, // Ё
  0x404,0xF2,0xAA,0xB4, // Є
  0x407,0xF4,0xAF,0xB7, // Ї
  0x406,0x49,0xB2,0xB6, // _ .*..
  0x405,0x53,0xBD,0x53, // _ .*.*
  // SMALL Cyrillic letters (base)
  0x430,0xA0,0xE0,0xC1, // а
  0x431,0xA1,0xE1,0xC2, // б
  0x432,0xA2,0xE2,0xD7, // в
  0x433,0xA3,0xE3,0xC7, // г
  0x434,0xA4,0xE4,0xC4, // д
  0x435,0xA5,0xE5,0xC5, // е
  0x436,0xA6,0xE6,0xD6, // ж
  0x437,0xA7,0xE7,0xDA, // з
  0x438,0xA8,0xE8,0xC9, // и
  0x439,0xA9,0xE9,0xCA, // й
  0x43A,0xAA,0xEA,0xCB, // к
  0x43B,0xAB,0xEB,0xCC, // л
  0x43C,0xAC,0xEC,0xCD, // м
  0x43D,0xAD,0xED,0xCE, // н
  0x43E,0xAE,0xEE,0xCF, // о
  0x43F,0xAF,0xEF,0xD0, // п
  0x440,0xE0,0xF0,0xD2, // р
  0x441,0xE1,0xF1,0xD3, // с
  0x442,0xE2,0xF2,0xD4, // т
  0x443,0xE3,0xF3,0xD5, // у
  0x444,0xE4,0xF4,0xC6, // ф
  0x445,0xE5,0xF5,0xC8, // х
  0x446,0xE6,0xF6,0xC3, // ц
  0x447,0xE7,0xF7,0xDE, // ч
  0x448,0xE8,0xF8,0xDB, // ш
  0x449,0xE9,0xF9,0xDD, // щ
  0x44A,0xEA,0xFA,0xDF, // ъ
  0x44B,0xEB,0xFB,0xD9, // ы
  0x44C,0xEC,0xFC,0xD8, // ь
  0x44D,0xED,0xFD,0xDC, // э
  0x44E,0xEE,0xFE,0xC0, // ю
  0x44F,0xEF,0xFF,0xD1, // я
  // SMALL Cyrillic letters (additional)
  0x452,'_',0x90,'_', // _ .*.*
  0x453,'_',0x83,'_', // _ .*.*
  0x459,'_',0x9A,'_', // _ .*.*
  0x45A,'_',0x9C,'_', // _ .*.*
  0x45C,'_',0x9D,'_', // _ .*.*
  0x45B,'_',0x9E,'_', // _ .*.*
  0x45F,'_',0x9F,'_', // _ .*.*
  0x45E,0xF7,0xA2,'_', // ў ...*
  0x458,0x6A,0xBC,0x6A, // _ .*.*
  0x491,0xA3,0xB4,0xAD, // _ .*..
  0x451,0xF1,0xB8,0xA3, // ё
  0x454,0xF3,0xBA,0xA4, // є
  0x457,0xF5,0xBF,0xA7, // ї
  0x456,0x69,0xB3,0xA6, // _ .*..
  0x455,0x73,0xBE,0x73, // _ .*.*
  0x0A0,'_',0xA0,0x20, // space .*..
  0x0A4,'_',0xA4,0xFD, // ¤   .*..
  0x0A6,'_',0xA6,'_', // ¦   .*.*
  0x0B0,0xF8,0xB0,0x9C, // °
  0x0B7,0xFA,0xB7,0x9E, // ·
  // 0x2022,,0x95,0x95, //    .*..
  // 0x2116,0xFC,0xB9,0x23, // №   ...*
  // 0x2219,,0xF9,0x9E, //    .*..
  // 0x221A,0xFB,,0x96, // v   ..*.
  // 0x25A0,0xFE,,0x94, // ¦
  0x0000,0,0,0
  };
  const TUNICODE2CHAR *p=unicode2char;
  unsigned int i;
  if (c<128) return(c);
  while((i=p->u)!=0)
  {
    if (c==i)
    {
      return(p->win);
    }
    p++;
  }
  c&=0xFF;
  if (c<32) return(' ');
  return(c);
}

int utf8_2_win1251(char *out, const char *in, int outsz)
{
  int c;
  char *old=out;
  while((c=*in++)!=0)
  {
    if ((c&0xE0)==0xC0)
    {
      if ((in[0]&0xC0)==0x80)
      {
	c&=0x1F;
	c<<=6;
	c|=(*in++)&0x3F;
      }
      else goto L_1251;
    }
    else
      if ((c&0xF0)==0xE0)
      {
	if (((in[0]&0xC0)==0x80)&&((in[1]&0xC0)==0x80))
	{
	  c&=0x0F;
	  c<<=12;
	  c|=((*in++)&0x3F)<<6;
	  c|=((*in++)&0x3F)<<0;
	}
        else break;
      }
  L_1251:
    if (outsz--)
    {
      *out++=char16to8(c);
    }
  }
  return out-old;
//  if (outsz) *out=0;
}

unsigned int char8to16(int c)
{
  if (c==0xA8) c=0x401;
  if (c==0xAA) c=0x404;
  if (c==0xAF) c=0x407;
  if (c==0xB8) c=0x451;
  if (c==0xBA) c=0x454;
  if (c==0xBF) c=0x457;
  if (c==0xB2) c=0x406;
  if (c==0xB3) c=0x456;
  if ((c>=0xC0)&&(c<0x100)) c+=0x350;
  return(c);
}

void win1251_2_utf8(string & out, const unsigned char *in)
{
        int c;
        while((c=char8to16(*in++))!=0)
        {
                if (c>=0x80)
                {
                        out+=(c>>6)|0xC0;
                        out+=(c&0x3F)|0x80;
                }
                else
                out+=c;
        }
}

//====================================================================
void MyIcqInterface::getMD5hash(vector<uint8_t> md5_salt, uint8_t * md5_hash){
    if (md5auth){
	NatICQ_PKT pkt;
	pkt.type=T_MD5AUTH;
	pkt.len=md5_salt.size();
	memcpy(pkt.data, &md5_salt[0], md5_salt.size());
	pkt.data[pkt.len]=0;
	NatICQTX(&pkt);
	do {
	    if (NatICQRX(naticq_sock,&pkt,60)<=0){
		break;
	    }
	} while(pkt.type!=T_MD5AUTH);
	memcpy(md5_hash,&pkt.data,16);
    }else{
	static uint8_t AOL_SALT_STR[]="AOL Instant Messenger (SM)";
	vector<uint8_t> auth_sum=md5_salt;
	if (mypassword.length()>8) auth_sum.insert(auth_sum.end(), (uint8_t*)mypassword.data(), ((uint8_t*)mypassword.data())+8);
	    else auth_sum.insert(auth_sum.end(), (uint8_t*)mypassword.data(), ((uint8_t*)mypassword.data())+mypassword.length());
	auth_sum.insert(auth_sum.end(), (uint8_t*)AOL_SALT_STR, ((uint8_t*)AOL_SALT_STR)+sizeof(AOL_SALT_STR)-1);
	calculate_md5((const char*)(&auth_sum[0]), auth_sum.size(), (char *)md5_hash);
    }
}
void MyIcqInterface::onAuthRequest(string from, string text)
{
        if (findCLUIN(from.c_str())>=0){
            NatICQ_PKT pkt;
	    pkt.uin=atoi(from.c_str());
	    pkt.type=T_RECVMSG;
            strcpy(pkt.data,"Auth REQ: ");
	    pkt.len=strlen(pkt.data);
//	        pkt.len+=utf8_2_win1251(pkt.data+pkt.len,text.c_str(),16383-pkt.len);
	    NatICQTX(&pkt);
	}
}

void MyIcqInterface::onAuthReply(string from, string text, uint8_t aflag)
{
        NatICQ_PKT pkt;
        pkt.uin=atoi(from.c_str());
        pkt.type=T_RECVMSG;
        strcpy(pkt.data,aflag?"Auth Resp OK!":"Auth resp failed, reason: ");
        pkt.len=strlen(pkt.data);
//        pkt.len+=utf8_2_win1251(pkt.data+pkt.len,text.c_str(),16383-pkt.len);
        NatICQTX(&pkt);
}

void MyIcqInterface::NatICQTX(NatICQ_PKT *p){
	int sz=p->len+8;
        send(naticq_sock,(char *)p,sz,0);
        total_sended+=sz;
        return;
}

void MyIcqInterface::onUserNotify(string uin, uint32_t stat1, uint32_t stat2, bool invis_flag, vector<uint8_t> xs)
{
        NatICQ_PKT pkt;
        pkt.uin=atoi(uin.c_str());
        pkt.type=T_STATUSCHANGE;
		if (invis_flag)
		{
				((uint32_t *)(pkt.data))[0]=STATUS_INVISIBLE;
		}
		else
		{
				memcpy(pkt.data,&stat2,2);
		}
		if (pkt.len=min(xs.size(),X_STATUS_MAX_BOUND)){
			memcpy(&pkt.data[2],&xs[0],pkt.len);
		}else{
			pkt.data[2]=0;
			pkt.len=1;
		}
		pkt.len+=2;
		NatICQTX(&pkt);
        int i=findCLUIN(uin);
        if ((i>=0)&&ContactListUins[i].clientid){
            pkt.len=utf8_2_win1251(pkt.data,ContactListUins[i].nick.c_str(),16383);
            pkt.data[pkt.len]='@';
	    pkt.len++;
	    pkt.type=T_CLENTRY;
	    NatICQTX(&pkt);
        }
}

void MyIcqInterface::onClientIDNotify(string uin, uint8_t clientid){
		NatICQ_PKT pkt;
		int i=findCLUIN(uin);
		if ((i>=0)&&clientid){
			pkt.uin=ContactListUins[i].groupid;
			pkt.len=0;
			pkt.type=T_GROUPFOLLOW;
			NatICQTX(&pkt);
			pkt.uin=atoi(uin.c_str());
			pkt.len=utf8_2_win1251(pkt.data,ContactListUins[i].nick.c_str(),16383);
			pkt.data[pkt.len]='@';
			pkt.len++;
			pkt.type=T_CLENTRY;
			NatICQTX(&pkt);
        }
}

void MyIcqInterface::onClientMsgAck(string uin, uint8_t *cookie)
{
        NatICQ_PKT pkt;
        pkt.uin=atoi(uin.c_str());
        pkt.type=T_CLIENT_ACK;
        pkt.len=2;
        memcpy(pkt.data, cookie+4, 2);
        NatICQTX(&pkt);
}

void MyIcqInterface::onServerMsgAck(string uin, uint8_t *cookie)
{
        NatICQ_PKT pkt;
        pkt.uin=atoi(uin.c_str());
        pkt.type=T_SRV_ACK;
        pkt.len=2;
        memcpy(pkt.data, cookie+4, 2);
        NatICQTX(&pkt);
}

void MyIcqInterface::onXstatusChanged(string uin, vector<uint8_t> x_status, string x_title, string x_descr)
{
		NatICQ_PKT pkt;
		int i=utf8_2_win1251(pkt.data+1,x_title.c_str(),255);
		pkt.data[0]=i;
		pkt.len=i+utf8_2_win1251(pkt.data+1+i,x_descr.c_str(),16383-256)+1;
		pkt.uin=atoi(uin.c_str());
		pkt.type=T_XTEXT_ACK;
		NatICQTX(&pkt);
}

void MyIcqInterface::onIncomingMsg(ICQKid2Message msg){
	NatICQ_PKT pkt;
	int i;
	size_t steps;
	switch (msg.enc_type){
		case ICQKid2Message::USASCII :
			i=msg.text.size();
			memcpy(pkt.data,&msg.text[0],i);
			pkt.len=i;
			break;
		case ICQKid2Message::LOCAL8BIT :
			i=msg.text.size();
			memcpy(pkt.data,&msg.text[0],i);
			pkt.len=i;
			break;
		case ICQKid2Message::UCS2BE :
			steps = msg.text.length()>>1;
			for (size_t i=0; i<steps; ++i)
				pkt.data[i]=char16to8((int)msg.text[i*2+1]+((int)msg.text[i*2]<<8));
			pkt.len=steps;
			break;
		case ICQKid2Message::UTF8 :
			pkt.len=utf8_2_win1251(pkt.data,msg.text.c_str(),16383);
			break;
	}
	if (findCLUIN(msg.uin)<0){
		if (pkt.data[0]=='4'){
			ICQKidFullUserInfo info;
			if (getFullUserInfo(msg.uin,info,true)){
				addBLMContact(msg.uin);
				pkt.uin=atoi(msg.uin.c_str());
				pkt.len=i=info.Nickname.size();
				memcpy(pkt.data,info.Nickname.c_str(),i);
				pkt.type=T_CLENTRY;
				NatICQTX(&pkt);
				sendMessage(MyIcqInterface::ICQKid2Message(msg.uin,"Antispam:\nOK",MyIcqInterface::ICQKid2Message::LOCAL8BIT),total_msg);
			}
		}else{
			sendMessage(MyIcqInterface::ICQKid2Message(msg.uin,"Antispam:\n2+2=?",MyIcqInterface::ICQKid2Message::LOCAL8BIT),total_msg);
#ifdef _WIN32
			Sleep(3000);
#else
			sleep(3);
#endif
			removeBLMContact(msg.uin);
			removeContact(msg.uin,NULL);
		}
	}else{
		pkt.type=T_RECVMSG;
		pkt.uin=atoi(msg.uin.c_str());
		NatICQTX(&pkt);
		if (msg.cookie_valid){
			if (ack_size==32){
				memcpy(ack_cache,ack_cache+1,sizeof(TACK)*31);
				ack_size--;
			}
			ack_cache[ack_size].SEQ=total_sended;
			ack_cache[ack_size].uin=pkt.uin;
			memcpy(ack_cache[ack_size].cookies,msg.cookie,8);
			ack_size++;
		}
	}
}

void MyIcqInterface::onSingOff(uint16_t err_code, string err_url)
{
		NatICQ_PKT pkt;
		pkt.len=sprintf(pkt.data,"Error code %d, url: %s",err_code,err_url.c_str());
        pkt.type=T_ERROR;
        NatICQTX(&pkt);
#ifdef _WIN32
        Sleep(3000);
#else
	sleep(3);
#endif
}

//---------------------------------------------------------------------------
#ifndef _WIN32
// Обработчики сигналов от ОС
int Must_stop = 0;

void SIGINT_Catcher(int sa) {
  printf("Caught SIGINT, exiting... Hit Ctrl-C once more to terminate immediately\n");
  Must_stop = 1;
  signal(SIGINT, SIG_DFL);
}


void SIGPIPE_Catcher(int sa) {
  printf("Caught SIGPIPE, probably some socket fucked-up\n");
  signal(SIGPIPE, SIGPIPE_Catcher);
}
#endif

typedef struct _t_param
{
  SOCKET s;
  uint32_t uin;
  sockaddr peer;
} THREAD_PARAM;

/* Прототип тела потока */
#ifdef _WIN32
unsigned int __stdcall ServerThread(LPVOID tParam);
#else
void *ServerThread(void *tParam);
#endif

#define BZERO(a) memset(a,0,sizeof(a))

#pragma argsused
int main(int argc, char* argv[])
{
  int listen_socket, server_socket;
  sockaddr_in server_addr, temp_addr;
  int accepted_len = sizeof(temp_addr);
  int port;

  // Проверка параметров
  if(argc < 2)
    {
      //                port=5050;
      //                goto DEFAULT_PORT;
      printf("Usage: %s PORT [/path/to/statistic/output]\n",      argv[0]);
      return -1;
    }
  port=atoi(argv[1]);
  if((port < 2) || (port > 65535))
    {
      printf("Incorrect port number. Value must be in range 2-65535\n");
      return -1;
    }
  printf("IG11 NatICQ server (rev %s)\n", __SVN_REVISION__);
  tzset();
#ifdef _WIN32
  printf("Win32 build\n");
  srand(GetTickCount());
#else
#ifdef __FreeBSD__
  printf("FreeBSD build\n");
#else
  printf("Linux build\n");  //в жопу гну
#endif //* FreeBSD * /
  printf("Thread stack size: %u\n", THREAD_STACK_SIZE);
  srand(time(NULL));	/* Инициализация RNG с помощью random(4) */
#endif //* _WIN32 * /

  if(argc==3)
    {
      StatOutput_Path = (char*)malloc(strlen(argv[2])+1);
      strcpy(StatOutput_Path, argv[2]);
      DPRINTF("stat outfile is %s\n",StatOutput_Path );
    }

    // 1.1. Инициализация WINSOCK

//DEFAULT_PORT:

#ifdef _WIN32
  WSADATA		WSAData;

  if(WSAStartup(MAKEWORD(2,0), &WSAData) != 0)
	{
		printf("WSAStartup() failed with error: %i\n", WSAGetLastError());
		return -1;
	}

	// 1.2. Создание "слушающего" сокета
	if((listen_socket = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
	{
		printf("socket() failed with error: %i\n", WSAGetLastError());
		return -1;
	}
        // Установка опции: REUSE ADDRESS.
        // Если сервер "упадёт" при подсоединённых клиентах
        // он сможет снова стартовать используя тот же порт.
	bool opt = true;
        if(SOCKET_ERROR == setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)))
        {
		printf("setsockopt(SO_REUSEADDR) failed with error: %i\n", WSAGetLastError());
		return -1;
        }
	//* 1.3. Привязка сокета к локальному адресу * /
	server_addr.sin_family      = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port        = htons(port);
	if(bind(listen_socket, (struct sockaddr *) &server_addr, sizeof(server_addr)) == SOCKET_ERROR)
	{
		printf("bind() failed with error: %i\n", WSAGetLastError());
		return -1;
	}
	/* 1.4. Включение прослушивания на серверном сокете */
	if(listen(listen_socket, 5) == SOCKET_ERROR)
	{
		printf("listen() failed with error: %i\n", WSAGetLastError());
		return -1;
	}
#else
	DPRINTF("Running FreeBSD sockets initialization\n");
	//* FreeBSD code * /
	setvbuf (stdout, 0, _IONBF, 0); // Отключение буферизации stdout
	// 1.2. Создание "слушающего" сокета
	if((listen_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
	  printf("socket() failed with error: %i\n", errno);
	  return -1;
	}
	assert(listen_socket!=0);
	//* 1.3. Привязка сокета к локальному адресу * /
	server_addr.sin_family      = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port        = htons(port);

	// Установка опции: REUSE ADDRESS.
	// Если сервер "упадёт" при подсоединённых клиентах
	// он сможет снова стартовать используя тот же порт.

	int opt = 1;
	if(-1 == setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))){
	    printf("setsockopt(SO_REUSEADDR) failed with error: %i\n", errno);
	  }

	/* Биндим сокет */
	if(::bind(listen_socket, (struct sockaddr *) &server_addr, sizeof(server_addr)) == -1) {
	  printf("bind() failed with error: %i\n", errno);
	  return -1;
	}

	//* 1.4. Включение прослушивания на серверном сокете * /
	if(listen(listen_socket, 5) == -1)
	{
		printf("listen() failed with error: %i\n", errno );
		return -1;
	}
	
	// Установка обработчиков сигналов
	signal(SIGINT, SIGINT_Catcher);
	signal(SIGPIPE, SIGPIPE_Catcher);
#endif  //* FreeBSD/Linux socket init * /

	ClientsCount = 0;
	Mutex_Init(CRIT_STAT);

	/* 1.5. Цикл принятия соединений от клиентов */
	THREAD_PARAM *t_param; // = NULL;
#ifdef _WIN32
		int peerlen  = sizeof(t_param->peer);
#else
		socklen_t peerlen  = sizeof(t_param->peer);
#endif

#ifdef _WIN32
	while((server_socket = accept(listen_socket, (struct sockaddr *) &temp_addr, (int *)&accepted_len)) != INVALID_SOCKET)
	  {
#else
	int thr_error = 0;
	pthread_t hThread;
	pthread_attr_t attr;

	while(!Must_stop)
	  {
	    server_socket = accept(listen_socket, (struct sockaddr *) &temp_addr, (socklen_t *)&accepted_len);
	    if(server_socket==-1){
	      printf("Socket error. Exit!!!, errno=%d\n",errno);
	      exit(1);
	    }

#ifdef __FreeBSD__
	    if(-1 == setsockopt(listen_socket, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt))){
	      printf("setsockopt(SO_NOSIGPIPE) failed with error: %i\n", errno);
	    }
#endif
#endif
		t_param = new THREAD_PARAM;

		if(NULL == t_param)
		{
			printf("memory allocation error!\n");
			break;
		}
		t_param->uin=0;
	    // Какой хост соединился с сервером ?

		if(0 == getpeername(server_socket, &(t_param->peer), &peerlen))
		{
			printf("Connect from %s:%i\n", inet_ntoa(((sockaddr_in *)&(t_param->peer))->sin_addr), ntohs(((sockaddr_in *)&(t_param->peer))->sin_port));
		}

		// Запуск потока для работы с сокетом и передача параметров
		// (динамическая память будет освобождена при выходе из потока)
		
		t_param->s   = server_socket;
//		strcpy(t_param->exe, argv[2]);

#ifdef _WIN32
		HANDLE hThread;
		// создаём поток с помощью _beginthreadex()
		if(NULL == (hThread = (HANDLE)_beginthreadex(NULL, 0, ServerThread, t_param, 0, NULL)))
		{
			printf("CreateThread() failed with error: %i\n", GetLastError());
		}
#else		
		int thr_error = 0;
		pthread_t hThread;
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		pthread_attr_setstacksize(&attr, THREAD_STACK_SIZE);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		if(thr_error = pthread_create(&hThread, &attr, ServerThread, t_param) != 0)
		  {
		    printf("pthread_create() failed with error: %i\n", thr_error);
		  }
#endif
		else
		  {
		    DPRINTF("New thread created, id=%X\n", hThread);
		    Mutex_Lock(CRIT_STAT);
		    ClientsCount++;
		    UpdateStatPage();
		    Mutex_Unlock(CRIT_STAT);
		  }
#ifndef _WIN32
		pthread_attr_destroy(&attr);
#endif

	}
	printf("Finished serving. Closing sockets and cleaning up...\n");
#ifdef _WIN32
	DWORD e=GetLastError();
	shutdown(listen_socket, 2);
	char buf[16];
	while(recv(listen_socket,buf,16,0)>0);
#else
	shutdown(listen_socket, SHUT_RDWR);
#endif

	Mutex_Destroy(CRIT_STAT);
	if(StatOutput_Path) free(StatOutput_Path);
	return 0;
}

int NatICQRX(int sock, NatICQ_PKT *p, int tmr)
{
 unsigned long res;
 fd_set rfds;
 struct timeval tv;

 res=0;
 if (ioctlsocket(sock,FIONREAD,&res)) return -1;
 if (res<8)
 {
  tv.tv_sec=tmr;
  tv.tv_usec=10000; //Ожидание 10мс
  FD_ZERO(&rfds);
  FD_SET(sock, &rfds);
//  if (!tmr) return 0;
  int sel_ret = select(sock+1, &rfds, NULL, NULL, &tv);
  if (sel_ret==0) return 0;
  if (sel_ret<0) return -1;
  if (!FD_ISSET(sock, &rfds)) return -1; //TNETWORK_ERR;
  res=0;
  if (ioctlsocket(sock,FIONREAD,&res)) return -1;
  if (res<1) return -1; //Обрыв связи
 }
 if (res<8) return 0;
 if (recv(sock,(char *)p,8,0)!=8) return -1;
 if (p->len>16383) return -1;
 if (!p->len) return 1;
 char *cp=p->data;
 int l=p->len;
 int i;
 while(l>0)
 {
  res=0;
  if (ioctlsocket(sock,FIONREAD,&res)) return -1;
  if (!res)
  {
   tv.tv_sec=120;
   tv.tv_usec=0;
   FD_ZERO(&rfds);
   FD_SET(sock, &rfds);
   int sel_ret = select(sock+1, &rfds, NULL, NULL, &tv);
   if (sel_ret==0) return -1;
   if (sel_ret<0) return -1;
   if (!FD_ISSET(sock, &rfds)) return -1; //TNETWORK_ERR;
   res=0;
   if (ioctlsocket(sock,FIONREAD,&res)) return -1;
  }
  if (res<1) return -1;
  if (res>(unsigned int)l) res=l;
  i=recv(sock,cp,res,0);
  if (i<=0) return -1;
  cp+=i;
  l-=i;
 }
 return 1;
}

void print_ssl_answer(char *s, unsigned short r)
{
 switch(r)
 {
 case SSI_EDIT_OK:
  strcpy(s,"OK");
  break;
 case SSI_EDIT_ERR_NOTFOUND:
  strcpy(s,"Not found");
  break;
 case SSI_EDIT_ERR_EXIST:
  strcpy(s,"Allready exist");
  break;
 case SSI_EDIT_ERR_NETWORK:
  strcpy(s,"Network error");
  break;
 case SSI_EDIT_ERR_CANTADD:
  strcpy(s,"Can't add");
  break;
 case SSI_EDIT_ERR_LIMIT:
  strcpy(s,"Limit reached");
  break;
 case SSI_EDIT_ERR_AIMLIST:
  strcpy(s,"AIM<->ICQ not alowed");
  break;
 case SSI_EDIT_ERR_NEEDAUTH:
  strcpy(s,"Contact need auth");
  break;
 default:
  sprintf(s,"Unknown code %u",r);
  break;
 }
}
                            static const unsigned long pr_statuses[5]=
                            {
                                PRIV_ALL_CAN_SEE,
                                PRIV_NOBODY_CAN_SEE,
                                PRIV_VISLIST_CAN_SEE,
                                PRIV_INVISLIST_CANNOT_SEE,
                                PRIV_CONTACTLIST_CAN_SEE,
                            };


#ifdef _WIN32
unsigned int __stdcall ServerThread(LPVOID tParam)
#else
void *ServerThread(void *tParam)
#endif
{
        THREAD_PARAM *param = (THREAD_PARAM *)tParam;
#ifdef _WIN32
        unsigned int s=param->s;
#else
        int s=param->s;
#endif
        int i;
        int j;
	char uin[32];
	unsigned short r=0;

        time_t naticq_timeout;
        MyIcqInterface miif;
        miif.naticq_sock=s;
        miif.subIGId=__SVN_REVISION__;
        NatICQ_PKT rpkt;
        DPRINTF("ServerThread started on socket %d\n", param->s);
	do{
                if (NatICQRX(s,&rpkt,60)<=0) goto L_ERR;
                if (rpkt.type==T_SETCLIENT_ID)
                {
                        rpkt.data[rpkt.len]=0;
                        rpkt.data[8]=0;
                        miif.subClientId=rpkt.data;
                }
        }
        while(rpkt.type!=T_REQLOGIN);

        miif.total_sended=0;
        miif.total_msg=0;
        miif.ack_size=0;
        miif.setNetworkTimeout(1200/3);

        if (rpkt.len){
            rpkt.data[rpkt.len]=0;
            miif.setPassword(rpkt.data);
            miif.md5auth=false;
            strcpy(rpkt.data,"Download new version!");
            rpkt.len=strlen(rpkt.data);
            rpkt.type=T_ERROR;
            miif.NatICQTX(&rpkt);
        }else{
	    miif.md5auth=true;
        }

        sprintf(rpkt.data,"%u",rpkt.uin);

        miif.setUIN(rpkt.data);
	param->uin = (uint32_t) rpkt.uin;
	printf("ICQ UIN is %u\n", param->uin);

        if (!miif.doConnect()){
	    printf("Connect failed at %d%% for %u\n",miif.connect_phase_percentage,param->uin);
	    sprintf(rpkt.data,"Connect failed at %d%%",miif.connect_phase_percentage);
        L_ERRTX:
                rpkt.len=strlen(rpkt.data);
                rpkt.uin=0;
                rpkt.type=T_ERROR;
                miif.NatICQTX(&rpkt);
#ifdef _WIN32
                Sleep(1000);
#else
		sleep(1);
#endif
                goto L_ERR;
        }

        rpkt.len=0;
        rpkt.type=T_LOGIN;
        miif.NatICQTX(&rpkt);
        i=0;
        j=miif.getMyPrivacyStatus();
        do
        {
                if (j==(int)pr_statuses[i]) break;
                i++;
        }
        while(i<5);
        rpkt.data[0]=i;
        rpkt.len=1;
        rpkt.type=T_LASTPRIVACY;
        miif.NatICQTX(&rpkt);
        for(i=0;i<(int)miif.ContactListGroups.size();i++)
        {
                rpkt.uin=miif.ContactListGroups[i].id;
                //memcpy(rpkt.data,&miif.ContactListGroups[i].name[0],rpkt.len=miif.ContactListGroups[i].name.size());
                rpkt.len=utf8_2_win1251(rpkt.data,miif.ContactListGroups[i].name.c_str(),16383);
                rpkt.type=T_GROUPID;
                miif.NatICQTX(&rpkt);
        }
        j=-1;
        for(i=0;i<(int)miif.ContactListUins.size();i++)
        {
                if (miif.ContactListUins[i].groupid!=j)
                {
                        j=miif.ContactListUins[i].groupid;
                        rpkt.uin=j;
                        rpkt.len=0;
                        rpkt.type=T_GROUPFOLLOW;
                        miif.NatICQTX(&rpkt);
                }
                rpkt.uin=atoi(miif.ContactListUins[i].uin.c_str());
                //memcpy(rpkt.data,&miif.ContactListUins[i].nick[0],rpkt.len=miif.ContactListUins[i].nick.size());
                rpkt.len=utf8_2_win1251(rpkt.data,miif.ContactListUins[i].nick.c_str(),16383);
                if (miif.ContactListUins[i].clientid){
            	    rpkt.data[rpkt.len]='@';
            	    rpkt.len++;
                }
                rpkt.type=T_CLENTRY;
                miif.NatICQTX(&rpkt);
        }
        rpkt.uin=0;
        rpkt.len=0;
        rpkt.type=T_CLENTRY;
        miif.NatICQTX(&rpkt);
        if (!miif.getOfflineMessages()) goto L_ERR;
        naticq_timeout=time(NULL)+300;
        while(true)
        {
                int net_ret=miif.pollIncomingEvents(1);
                if (net_ret!=TNETWORK_TIMEOUT && net_ret!=1) goto L_ERR;
                if ((i=NatICQRX(s,&rpkt,0))<0) break;
                if (!i)
                {
                        if (time(NULL)<naticq_timeout) continue;
                        break; //Таймаут
                }
                naticq_timeout=time(NULL)+300;
				switch(rpkt.type)
                {
		case 0:		/* Keep-alive */
		    break;

                case T_SENDMSG:
                        {
                                char s[32];
                                sprintf(s,"%u",rpkt.uin);
                                int uen_ind=miif.findCLUIN(s);
                                rpkt.data[rpkt.len]=0;
                                miif.total_msg=(miif.total_msg+1)&0x7FFF;
                                if ( (uen_ind>=0) &&
                                     (miif.ContactListUins[uen_ind].srv_relay_cap) &&
                                     (miif.ContactListUins[uen_ind].online_status!=STATUS_OFFLINE)
                                   )
                                {
                                        if (miif.ContactListUins[uen_ind].unicode_cap)
                                        {
                                                string utf;
                                                win1251_2_utf8(utf, (unsigned char*)rpkt.data);
                                                if (!miif.sendMessage(MyIcqInterface::ICQKid2Message(s,utf,MyIcqInterface::ICQKid2Message::UTF8),miif.total_msg)) goto L_OLDMSG;
                                        }
                                        else
                                        {
                                                if (!miif.sendMessage(MyIcqInterface::ICQKid2Message(s,rpkt.data,MyIcqInterface::ICQKid2Message::UTF8),miif.total_msg)) goto L_OLDMSG;
                                        }
                                }
                                else
                                {
                                L_OLDMSG:
                                        miif.sendMessage(MyIcqInterface::ICQKid2Message(s,rpkt.data,MyIcqInterface::ICQKid2Message::LOCAL8BIT),miif.total_msg);
                                }
                        }
                        break;
                case T_MSGACK:
                        for(i=0; i<miif.ack_size; i++)
                        {
                                if (miif.ack_cache[i].SEQ==rpkt.uin)
                                {
                                        sprintf(rpkt.data,"%u",miif.ack_cache[i].uin);
                                        (void)miif.sendMsgAutoResponse(rpkt.data, (uint8_t*)miif.ack_cache[i].cookies, MSG_TYPE_PLAINTEXT); // Plain text
                                        memmove(miif.ack_cache+i,miif.ack_cache+i+1,sizeof(TACK)*(31-i));
                                        miif.ack_size--;
                                        break;
                                }
                        }
                        break;
                case T_XTEXT_REQ:
                        sprintf(rpkt.data,"%u",rpkt.uin);
                        miif.sendXtrazRequest(rpkt.data);
                        break;
                case T_MY_XSTATUS_CH:
						if ((i=rpkt.data[0])<=X_STATUS_MAX_BOUND)
                        {
                                miif.setXStatus(i,miif.xStatusTitle,miif.xStatusDescription);
						}
                        break;
                case T_MY_STATUS_CH:
                        if ((i=rpkt.data[0])<13)
                        {
                            static const unsigned long statuses[13]=
                            {
                                STATUS_OFFLINE,
                                STATUS_INVISIBLE,
                                STATUS_AWAY,
                                STATUS_NA,
                                STATUS_OCCUPIED,
                                STATUS_DND,
                                STATUS_DEPRESSION,
                                STATUS_EVIL,
                                STATUS_HOME,
                                STATUS_LUNCH,
                                STATUS_WORK,
                                STATUS_ONLINE,
                                STATUS_FREE4CHAT
                            };
                            miif.setStatus(statuses[i]);
                        }
                        break;
                case T_ECHO:
                        rpkt.type=T_ECHORET;
                        miif.NatICQTX(&rpkt);
                        break;
                case T_REQINFOSHORT:
                        {
                                ICQKidFullUserInfo info;
                                sprintf(rpkt.data,"%u",rpkt.uin);
                                miif.getFullUserInfo(rpkt.data,info,true);
//                                rpkt.len=0;
#ifdef WIN32
								rpkt.len=_snprintf(rpkt.data,16383,
#else
								rpkt.len=snprintf(rpkt.data,16383,
#endif
                                "Nick: %s\r\n"
                                "Firstname: %s\r\n"
                                "Lastname: %s\r\n"
                                "Age: %d\r\n"
                                "Gender: %s\r\n"
                                "Homecity: %s\r\n"
                                "Notes: %s\r\n",
                                info.Nickname.c_str(),
                                info.Firstname.c_str(),
                                info.Lastname.c_str(),
                                info.Age,
                                ((info.Gender==1)||(info.Gender==2))?(info.Gender==2?"Male":"Female"):"Unknown",
                                info.Homecity.c_str(),
                                info.Notes.c_str()
                                );
/*                                rpkt.len+=snprintf(rpkt.data+rpkt.len,16383-rpkt.len,"Nick: "); if (rpkt.len==16383) goto L1;
                                rpkt.len+=utf8_2_win1251(rpkt.data+rpkt.len,info.Nickname.c_str(),16383-rpkt.len);
                                rpkt.len+=snprintf(rpkt.data+rpkt.len,16383-rpkt.len,"\nFirstname: "); if (rpkt.len==16383) goto L1;
                                rpkt.len+=utf8_2_win1251(rpkt.data+rpkt.len,info.Firstname.c_str(),16383-rpkt.len);
                                rpkt.len+=snprintf(rpkt.data+rpkt.len,16383-rpkt.len,"\nLastname: "); if (rpkt.len==16383) goto L1;
                                rpkt.len+=utf8_2_win1251(rpkt.data+rpkt.len,info.Lastname.c_str(),16383-rpkt.len);
                                rpkt.len+=snprintf(rpkt.data+rpkt.len,16383-rpkt.len,"\nNotes: "); if (rpkt.len==16383) goto L1;
                                rpkt.len+=utf8_2_win1251(rpkt.data+rpkt.len,info.Notes.c_str(),16383-rpkt.len);
*///                                L1:
                                rpkt.type=T_RECVMSG;
                                miif.NatICQTX(&rpkt);
                        }
                        break;
                case T_AUTHREQ:
                        {
                                char s[32];
                                rpkt.data[rpkt.len]=0;
                                sprintf(s,"%u",rpkt.uin);
                                miif.authRequest(s,"");
                        }
                        break;
                case T_AUTHGRANT:
                        {
                                char s[32];
                                rpkt.data[rpkt.len]=0;
                                sprintf(s,"%u",rpkt.uin);
                                miif.authReply(s,"",AUTH_ACCEPTED);
                        }
                        break;
                case T_XTEXT_SET:
                        {
                                string t;
                                string d;
                                rpkt.data[rpkt.len]=0;
                                win1251_2_utf8(t,(unsigned char*)rpkt.data);
                                win1251_2_utf8(d,(unsigned char*)rpkt.data+strlen(rpkt.data)+1);
                                miif.setXStatus(miif.xStatus,t,d);
                                break;
                        }
                case T_ADDCONTACT:
                        {
                                string grp;
                                char uin[32];
                                string nick;
                                unsigned short r=0;
                                rpkt.data[rpkt.len]=0;
                                sprintf(uin,"%u",rpkt.uin);
                                if (miif.ContactListGroups.size()>0)
                                        grp=miif.ContactListGroups[0].name;
                                else
                                        grp="";
                                win1251_2_utf8(nick,(unsigned char *)rpkt.data);
                                if (miif.findCLUIN(uin)<0)
                                {
                                        miif.addContact(uin,nick,grp,&r);
                                }
                                else
                                {
                                        miif.renameContact(uin,nick,&r);
                                }
                                if (r==SSI_EDIT_OK)
                                {
                                        int i=miif.findCLGroup(grp);
                                        if (i>=0)
                                        {
                                                rpkt.uin=miif.ContactListGroups[i].id;
                                                rpkt.len=0;
                                                rpkt.type=T_GROUPFOLLOW;
                                                miif.NatICQTX(&rpkt);
                                        }
                                        rpkt.uin=atoi(uin);
                                        rpkt.len=utf8_2_win1251(rpkt.data,nick.c_str(),16383);
                                        rpkt.type=T_CLENTRY;
                                        miif.NatICQTX(&rpkt);
                                        rpkt.uin=0;
                                        rpkt.len=0;
                                        rpkt.type=T_CLENTRY;
                                        miif.NatICQTX(&rpkt);
                                }
                                print_ssl_answer(rpkt.data,r);
                                rpkt.uin=0;
                                rpkt.type=T_SSLRESP;
                                rpkt.len=strlen(rpkt.data);
                                miif.NatICQTX(&rpkt);
                                break;
                        }
                case T_ADDCONTACT_WITH_GRP:
                        {
                                int gi;
                                string grp;
                                char uin[32];
                                string nick;
                                unsigned short r=0;
                                rpkt.data[rpkt.len]=0;
                                sprintf(uin,"%u",rpkt.uin);
                                gi=miif.findCLGroup(*((unsigned int *)(rpkt.data)));
                                if (gi>=0)
                                {
                                        grp=miif.ContactListGroups[gi].name;
                                }
                                else
                                {
                                if (miif.ContactListGroups.size()>0)
                                        grp=miif.ContactListGroups[0].name;
                                else
                                        grp="";
                                }
                                win1251_2_utf8(nick,(unsigned char *)rpkt.data+4);
                                if (miif.findCLUIN(uin)<0)
                                {
                                        miif.addContact(uin,nick,grp,&r);
                                }
                                else
                                {
                                        miif.removeContact(uin,&r);
                                        miif.addContact(uin,nick,grp,&r);
                                }
                                if (r==SSI_EDIT_OK)
                                {
                                        int i=miif.findCLGroup(grp);
                                        if (i>=0)
                                        {
                                                rpkt.uin=miif.ContactListGroups[i].id;
                                                rpkt.len=0;
                                                rpkt.type=T_GROUPFOLLOW;
                                                miif.NatICQTX(&rpkt);
                                        }
                                        rpkt.uin=atoi(uin);
                                        rpkt.len=utf8_2_win1251(rpkt.data,nick.c_str(),16383);
                                        rpkt.type=T_CLENTRY;
                                        miif.NatICQTX(&rpkt);
                                        rpkt.uin=0;
                                        rpkt.len=0;
                                        rpkt.type=T_CLENTRY;
                                        miif.NatICQTX(&rpkt);
                                }
                                print_ssl_answer(rpkt.data,r);
                                rpkt.uin=0;
                                rpkt.type=T_SSLRESP;
                                rpkt.len=strlen(rpkt.data);
                                miif.NatICQTX(&rpkt);
                                break;
                        }
			
		case T_REMOVECONTACT:
			/* Fuck up contact */
			
			rpkt.data[rpkt.len]=0;
			sprintf(uin,"%u",rpkt.uin);
			
			miif.removeContact(uin,&r);
			
			if (r==SSI_EDIT_OK) {
				rpkt.type=T_CONTACTREMOVED;
				rpkt.len=0;
				miif.NatICQTX(&rpkt);
				
			}else{
				rpkt.len=sprintf(rpkt.data,"Error! Expected %d, got %d", SSI_EDIT_OK, r);
				rpkt.type=T_ERROR;
				miif.NatICQTX(&rpkt);
			}
			print_ssl_answer(rpkt.data,r);
			rpkt.uin=0;
			rpkt.type=T_SSLRESP;
			rpkt.len=strlen(rpkt.data);
			miif.NatICQTX(&rpkt);
			break;
			
                case T_SETPRIVACY:
                        if ((i=rpkt.data[0])<5)
                        {
                            miif.setMyPrivacyStatus(pr_statuses[i]);
                        }
                        break;

		default:
			/* Unknown opcode */
			
			DPRINTF("%u: unknown opcode \"%u\" received!\n", param->uin, rpkt.type);
			rpkt.len=sprintf(rpkt.data,"Unknown opcode %u", rpkt.type);
			rpkt.type=T_ERROR;
			miif.NatICQTX(&rpkt);
			break;
                }
//
        }
        miif.doDisconnect();
    	// Сообщить кто отключился
L_ERR:

	printf("Disconnect from %s:%i\n", inet_ntoa(((sockaddr_in *)&(param->peer))->sin_addr), ntohs(((sockaddr_in *)&(param->peer))->sin_port));
	
#ifdef _WIN32
	int me=0;
#else
	pthread_t me;
	me = pthread_self();
#endif
	printf("Thread %X (uin %u) received disconnect!\n", me, param->uin);
	// Закрыть сокет и освободить память переданной структуры
#ifdef _WIN32
	shutdown(s, 2); //SD_BOTH);
	closesocket(s);
#else
	shutdown(s, SHUT_RDWR);	/* Shutdown socket, disallow further reads and writes */
	close(s);		/* Close handle */
#endif
	delete param;
	param = NULL;

	Mutex_Lock(CRIT_STAT);
	ClientsCount--;
	UpdateStatPage();
	Mutex_Unlock(CRIT_STAT);
	return 0; /* Эквивалентно pthread_exit(), но при этом вызываются нужные деструкторы */
}
//---------------------------------------------------------------------------

/*
 * Local Variables: *
 * c-file-style: "bsd" *
 * End: *
 */
