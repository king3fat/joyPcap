// AnalyzeIEC101.cpp: implementation of the AnalyzeIEC101 class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "PcapAgent.h"

#include <winsock.h>
#pragma comment(lib, "wsock32.lib")

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

#define MTRACEBUFLEN   3000

#define MON_SEND			0			/**< 通讯监视方向发送 */
#define MON_RECV			1			/**< 通讯监视方向接收 */

#define MON_COM				1			/**< 端口类型串口 */
#define MON_TCP				2			/**< 端口类型TCP  */
#define MON_UDP				3			/**< 端口类型UDP  */
#define	MON_LOG				4			/**< 信息类型　　 */

#pragma pack(push,1)
typedef struct monbuf_t monbuf_t;
struct monbuf_t {
    unsigned char	sync_code[4];			/**< 同步字 EB 90 EB 90 */
    unsigned char	type;					/**< 端口类型：MON_COM / MON_TCP / MON_UDP */
    unsigned char	orient;					/**< 监视的方向：MON_SEND / MON_RECV */
    unsigned int	localhost;				/**< TCP或UDP时表示本机IP地址 */
    unsigned short	localport;				/**< TCP或UDP时表示本机端口号 */
    unsigned int	remotehost;				/**< TCP或UDP时表示对端IP地址 */
    unsigned short	remoteport;				/**< TCP或UDP时表示对端端口号 */
	unsigned char	erial_name[16];		    /**< 串口名称 */
	unsigned char	serial_len;				/**< 串口名称长度 */
	unsigned int	node_id;				/**< 节点号  */
	unsigned char	node_name[32];			/**< 节点名称 */
	unsigned char	node_len;				/**< 节点名称长度 */	
	unsigned int	ied_id;					/**< 装置号 */
	unsigned char	ied_name[32];			/**< 装置名称 */
	unsigned char	ied_len;				/**< 装置名称长度 */
	unsigned int	len;					/**< 有效数据长度(数据**data的长度) */
	//在待发送数据数据缓冲区后增加四字节(uint32_t)，用于代表主备机及多机
};
#pragma pack(pop)

typedef struct mac_head_t mac_head_t;
struct mac_head_t{
 char m_cDstMacAddress[6];    //目的mac地址
 char m_cSrcMacAddress[6];    //源mac地址
 short m_cType;                 //上一层协议类型，如0x0800代表上一层是IP协议，0x0806为arp
};

typedef struct ip_head_t ip_head_t;
struct ip_head_t
{
 char m_cVersionAndHeaderLen;   //版本信息(前4位)，头长度(后4位)
 char m_cTypeOfService;         // 服务类型8位
 short m_sTotalLenOfPacket;     //数据包长度
 short m_sPacketID;             //数据包标识
 short m_sSliceinfo;            //分片使用
 char m_cTTL;                   //存活时间
 char m_cTypeOfProtocol;        //协议类型
 short m_sCheckSum;             //校验和
 unsigned int m_uiSourIp;       //源ip
 unsigned int m_uiDestIp;       //目的ip
};

typedef struct tcp_head_t tcp_head_t;
struct tcp_head_t
{
 unsigned short m_sSourPort;            // 源端口号16bit
 unsigned short m_sDestPort;            // 目的端口号16bit
 unsigned int m_uiSequNum;              // 序列号32bit
 unsigned int m_uiAcknowledgeNum;       // 确认号32bit
 short m_sHeaderLenAndFlag;             // 前4位：TCP头长度；中6位：保留；后6位：标志位
 short m_sWindowSize;                   // 窗口大小16bit
 short m_sCheckSum;                     // 检验和16bit
 short m_surgentPointer;                // 紧急数据偏移量16bit
};

typedef struct udp_head_t udp_head_t;
struct udp_head_t
{
 unsigned short m_usSourPort;           // 源端口号16bit
 unsigned short m_usDestPort;           // 目的端口号16bit
 unsigned short m_usLength;             // 数据包长度16bit
 unsigned short m_usCheckSum;           // 校验和16bit
};

typedef bool        (*PcapInit)();
typedef bool        (*PcapExit)();

typedef bool        (*PcapAdapterList)(short adapter, char* name);
typedef bool        (*PcapAdapterOpen)(short adapter);
typedef bool        (*PcapAdapterClose)(short adapter);

typedef bool        (*PcapAddFilter)(short type, long val);
typedef void        (*PcapClearFilter)();

typedef short       (*PcapCapture)(char* packet, short tmout, short *adapter);

PcapInit            fnPcapInit = NULL;
PcapExit            fnPcapExit = NULL;
PcapAdapterList     fnPcapAdapterList = NULL;
PcapAdapterOpen     fnPcapAdapterOpen = NULL;
PcapAdapterClose    fnPcapAdapterClose = NULL;
PcapAddFilter       fnPcapAddFilter = NULL;
PcapClearFilter     fnPcapClearFilter = NULL;
PcapCapture         fnPcapCapture = NULL;

static bool g_CaptureSwitch = false;
UINT PcapCaptureThread(LPVOID pParam)
{
    CPcapAgent* pagent = (CPcapAgent*)pParam;
    mac_head_t  *mac;
    ip_head_t   *ip;
    tcp_head_t  *tcp;
    SOCKET      ss;
    sockaddr_in addr;
    struct in_addr ia;

    monbuf_t    *monbuf;
    char packet[4096];
    char sendbuf[4096] = {'\0'};
    int len, tcp_udp_len;
    short adapter;

    monbuf = (monbuf_t*)sendbuf;
    //socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	ss = socket(PF_INET, SOCK_DGRAM, 0);
	if ( ss == INVALID_SOCKET )
	{
        g_CaptureSwitch = false;
		return false;
	}

    addr.sin_family = AF_INET;
    addr.sin_port = htons(5550);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    monbuf->sync_code[0] = 0xEB;
    monbuf->sync_code[1] = 0x90;
    monbuf->sync_code[2] = 0xEB;
    monbuf->sync_code[3] = 0x90;

    monbuf->node_id = 1104;
    memcpy((char*)monbuf->node_name,  "joyPcap网络抓包", strlen("joyPcap网络抓包"));
    monbuf->node_len = (char)strlen("joyPcap网络抓包");

    while(g_CaptureSwitch){
        len = fnPcapCapture(packet, 3, &adapter);

        if(adapter != pagent->GetCurrentAdapter()) continue;

        if(len < sizeof(mac_head_t) + sizeof(ip_head_t))  continue;

        mac = (mac_head_t*)packet;
        if(mac->m_cType != 0x08)  continue;

        ip = (ip_head_t*)(packet + sizeof(mac_head_t));
        if(ip->m_cTypeOfProtocol == 0x06){
            if(len < sizeof(mac_head_t) + sizeof(ip_head_t) + sizeof(tcp_head_t))    continue;
            tcp_udp_len = sizeof(tcp_head_t);
            monbuf->type = MON_TCP;
        }else if(ip->m_cTypeOfProtocol == 0x11){
            if(len < sizeof(mac_head_t) + sizeof(ip_head_t) + sizeof(udp_head_t))    continue;
            tcp_udp_len = sizeof(udp_head_t);
            monbuf->type = MON_UDP;
        }else{
            continue;
        }

        tcp = (tcp_head_t*)(packet + sizeof(mac_head_t)+ sizeof(ip_head_t));
        if(ip->m_uiDestIp >= ip->m_uiSourIp){
            monbuf->orient       = MON_SEND;
            monbuf->localhost    = ip->m_uiSourIp;
            monbuf->localport    = tcp->m_sSourPort;
            monbuf->remotehost   = ip->m_uiDestIp;
            monbuf->remoteport   = tcp->m_sDestPort;
        }else{
            monbuf->orient       = MON_RECV;
            monbuf->localhost    = ip->m_uiDestIp;
            monbuf->localport    = tcp->m_sDestPort;
            monbuf->remotehost   = ip->m_uiSourIp;
            monbuf->remoteport   = tcp->m_sSourPort;

        }

        monbuf->ied_id = LOWORD(monbuf->remotehost);
        ia.S_un.S_addr = monbuf->remotehost;
        strcpy((char*)monbuf->ied_name, inet_ntoa(ia));
        monbuf->ied_len = (char)strlen((char*)monbuf->ied_name);
        //htons
        len -= (sizeof(mac_head_t) + sizeof(ip_head_t) + tcp_udp_len);
        monbuf->len = len;
        memcpy(sendbuf + sizeof(monbuf_t), packet + sizeof(mac_head_t) + sizeof(ip_head_t) + tcp_udp_len, len);
        sendbuf[len+sizeof(monbuf_t)] =   0x7F;
        sendbuf[len+sizeof(monbuf_t)+1] = 0x00;
        sendbuf[len+sizeof(monbuf_t)+2] = 0x00;
        sendbuf[len+sizeof(monbuf_t)+3] = 0x1;
        sendbuf[len+sizeof(monbuf_t)+4] = '\0';
        sendto(ss, sendbuf, sizeof(monbuf_t)+ len + 4, 0, (SOCKADDR *)&addr, sizeof(addr));
    }

    return 0;
}

CPcapAgent::CPcapAgent()
{
    m_hPcapDll = LoadLibrary(PCAPDLL_NAME);
}

CPcapAgent::~CPcapAgent()
{
    fnPcapExit();
    if(m_hPcapDll)  FreeLibrary(m_hPcapDll);
}

bool CPcapAgent::Init()
{

    if(m_hPcapDll == NULL)  return false;

    fnPcapInit = (PcapInit)GetProcAddress(m_hPcapDll, "joyPcapInit");
    fnPcapExit = (PcapExit)GetProcAddress(m_hPcapDll, "joyPcapExit");

    fnPcapAdapterList = (PcapAdapterList)GetProcAddress(m_hPcapDll, "joyPcapAdapterList");
    fnPcapAdapterOpen = (PcapAdapterOpen)GetProcAddress(m_hPcapDll, "joyPcapAdapterOpen");
    fnPcapAdapterClose= (PcapAdapterClose)GetProcAddress(m_hPcapDll, "joyPcapAdapterClose");

    fnPcapAddFilter   = (PcapAddFilter)GetProcAddress(m_hPcapDll, "joyPcapAddFilter");
    fnPcapClearFilter = (PcapClearFilter)GetProcAddress(m_hPcapDll, "joyPcapClearFilter");

    fnPcapCapture     = (PcapCapture)GetProcAddress(m_hPcapDll, "joyPcapCapture");

    if(fnPcapInit == NULL || fnPcapExit == NULL || fnPcapAdapterList == NULL 
     ||fnPcapAdapterOpen == NULL || fnPcapAdapterClose == NULL || fnPcapAddFilter == NULL 
     ||fnPcapClearFilter == NULL || fnPcapCapture == NULL){
        FreeLibrary(m_hPcapDll);
        return false;
    }

    fnPcapInit();
    return true;
}

bool CPcapAgent::Start(int adapter)
{
    char aname[256] = {'\0'};

    if(m_hPcapDll == NULL || fnPcapAdapterOpen == NULL)  return false;

    if(false == fnPcapAdapterList(adapter, NULL))  return false;

    if(g_CaptureSwitch) return true;

    if(fnPcapAdapterOpen(adapter)){
        g_CaptureSwitch = true;
        m_CurrentAdapter = LOWORD(adapter);
        AfxBeginThread(PcapCaptureThread, this);
        Sleep(2000);
    }
    return g_CaptureSwitch;
}

bool CPcapAgent::Stop()
{
    if(g_CaptureSwitch == false) return true;

    g_CaptureSwitch = false;
    Sleep(2000);
    fnPcapAdapterClose(m_CurrentAdapter);
    return true;
}

CString CPcapAgent::GetAdapterName(int adapter)
{
    char namebuf[128];
    fnPcapAdapterList(adapter, namebuf);
    return CString(namebuf);
    //char namebuf[128]={'\0'}, *index;
    //if(m_hPcapDll == NULL || fnPcapAdapterList == NULL)  return "";

    //if(false == fnPcapAdapterList(adapter, namebuf))    return "";

    //if(NULL == (index = strstr(namebuf, "rpcap")))   return "";

    //index += 8; //"rpcap://"

    //CString AdapterName(index);
    //HKEY hKey;

    //CString strKeyName("SYSTEM\\ControlSet001\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\");
    //strKeyName += AdapterName.Mid(12);
    //strKeyName += "\\Connection";

    //if(RegOpenKeyEx(HKEY_LOCAL_MACHINE,
    //    LPCTSTR(strKeyName),
    //    0,
    //    KEY_READ,
    //    &hKey) != ERROR_SUCCESS)
    //{
    //    return "";
    //}

    //unsigned char szData[256];
    //DWORD dwBufSize;
	
    //CString temp;

    //dwBufSize = sizeof(szData);
    //if(RegQueryValueEx(hKey, TEXT("Name"), 0, 0, szData, &dwBufSize) == ERROR_SUCCESS)
    //{	
    //   return CString(szData);
    //}
    //return "";
}

bool    CPcapAgent::AddFilter(short type, long val)
{
    return fnPcapAddFilter(type, val);
}

void    CPcapAgent::ClearFilter()
{
    fnPcapClearFilter();
}
