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

#define MON_SEND			0			/**< ͨѶ���ӷ����� */
#define MON_RECV			1			/**< ͨѶ���ӷ������ */

#define MON_COM				1			/**< �˿����ʹ��� */
#define MON_TCP				2			/**< �˿�����TCP  */
#define MON_UDP				3			/**< �˿�����UDP  */
#define	MON_LOG				4			/**< ��Ϣ���͡��� */

#pragma pack(push,1)
typedef struct monbuf_t monbuf_t;
struct monbuf_t {
    unsigned char	sync_code[4];			/**< ͬ���� EB 90 EB 90 */
    unsigned char	type;					/**< �˿����ͣ�MON_COM / MON_TCP / MON_UDP */
    unsigned char	orient;					/**< ���ӵķ���MON_SEND / MON_RECV */
    unsigned int	localhost;				/**< TCP��UDPʱ��ʾ����IP��ַ */
    unsigned short	localport;				/**< TCP��UDPʱ��ʾ�����˿ں� */
    unsigned int	remotehost;				/**< TCP��UDPʱ��ʾ�Զ�IP��ַ */
    unsigned short	remoteport;				/**< TCP��UDPʱ��ʾ�Զ˶˿ں� */
	unsigned char	erial_name[16];		    /**< �������� */
	unsigned char	serial_len;				/**< �������Ƴ��� */
	unsigned int	node_id;				/**< �ڵ��  */
	unsigned char	node_name[32];			/**< �ڵ����� */
	unsigned char	node_len;				/**< �ڵ����Ƴ��� */	
	unsigned int	ied_id;					/**< װ�ú� */
	unsigned char	ied_name[32];			/**< װ������ */
	unsigned char	ied_len;				/**< װ�����Ƴ��� */
	unsigned int	len;					/**< ��Ч���ݳ���(����**data�ĳ���) */
	//�ڴ������������ݻ��������������ֽ�(uint32_t)�����ڴ��������������
};
#pragma pack(pop)

typedef struct mac_head_t mac_head_t;
struct mac_head_t{
 char m_cDstMacAddress[6];    //Ŀ��mac��ַ
 char m_cSrcMacAddress[6];    //Դmac��ַ
 short m_cType;                 //��һ��Э�����ͣ���0x0800������һ����IPЭ�飬0x0806Ϊarp
};

typedef struct ip_head_t ip_head_t;
struct ip_head_t
{
 char m_cVersionAndHeaderLen;   //�汾��Ϣ(ǰ4λ)��ͷ����(��4λ)
 char m_cTypeOfService;         // ��������8λ
 short m_sTotalLenOfPacket;     //���ݰ�����
 short m_sPacketID;             //���ݰ���ʶ
 short m_sSliceinfo;            //��Ƭʹ��
 char m_cTTL;                   //���ʱ��
 char m_cTypeOfProtocol;        //Э������
 short m_sCheckSum;             //У���
 unsigned int m_uiSourIp;       //Դip
 unsigned int m_uiDestIp;       //Ŀ��ip
};

typedef struct tcp_head_t tcp_head_t;
struct tcp_head_t
{
 unsigned short m_sSourPort;            // Դ�˿ں�16bit
 unsigned short m_sDestPort;            // Ŀ�Ķ˿ں�16bit
 unsigned int m_uiSequNum;              // ���к�32bit
 unsigned int m_uiAcknowledgeNum;       // ȷ�Ϻ�32bit
 short m_sHeaderLenAndFlag;             // ǰ4λ��TCPͷ���ȣ���6λ����������6λ����־λ
 short m_sWindowSize;                   // ���ڴ�С16bit
 short m_sCheckSum;                     // �����16bit
 short m_surgentPointer;                // ��������ƫ����16bit
};

typedef struct udp_head_t udp_head_t;
struct udp_head_t
{
 unsigned short m_usSourPort;           // Դ�˿ں�16bit
 unsigned short m_usDestPort;           // Ŀ�Ķ˿ں�16bit
 unsigned short m_usLength;             // ���ݰ�����16bit
 unsigned short m_usCheckSum;           // У���16bit
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
    memcpy((char*)monbuf->node_name,  "joyPcap����ץ��", strlen("joyPcap����ץ��"));
    monbuf->node_len = (char)strlen("joyPcap����ץ��");

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
