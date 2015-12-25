#include "stdafx.h"
#include "joyPcapExport.h"
#include "pcap.h"
#include "afxmt.h"
#include<deque>
#include"winsock2.h"
#include <Iphlpapi.h> 

#pragma comment(lib, "Iphlpapi.lib")

#define MAX_INTERFACE_NAME 128

short g_adapter_count = 0;
struct in_addr g_adapter_addrs[MAX_INTERFACE];
struct in_addr g_adapter_mask[MAX_INTERFACE];
struct in_addr g_adapter_gateway[MAX_INTERFACE];
unsigned char  g_mac_addrs[MAX_INTERFACE][6];

struct in_addr g_dns[2];

short g_filter_protocol = 0;
short g_filter_port = 0;
int  g_filter_ipaddr[8];
char g_filter_macaddr[6];
char g_adapter_names[MAX_INTERFACE][MAX_INTERFACE_NAME];

bool    g_open[MAX_INTERFACE] = {false};
pcap_t* g_hpcap[MAX_INTERFACE]= {NULL};

std::deque<char*> deq_buffer;
CCriticalSection  cs;

void DispatchCallback(u_char* arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
    //printf("adapter: %s reccive packet length %d, caplen = %d\n", p->adapter_name, pkthdr->len, pkthdr->caplen);
    short adapter = (short)arg;

    if(!g_open[adapter])   return;

    char *b = (char*)malloc(pkthdr->len+3);

    b[0] = LOBYTE(adapter);
    b[1] = LOBYTE(pkthdr->len);
    b[2] = HIBYTE(pkthdr->len);
    memcpy(&b[3], packet, pkthdr->len);
    
    cs.Lock();
    deq_buffer.push_back(b);
    cs.Unlock();
}

char* MakeFilter()
{
    static char filter[1024];
    char format[128];
    bool filter_head = true;
    bool ip_head = true;
    bool pro_head = true;
    struct in_addr ia;

    filter[0] = '\0';

    for(int i = 0; i < sizeof(g_filter_ipaddr) && g_filter_ipaddr[i] != 0; ++i){
        if(filter_head){    
            strcat(filter, "("); 
            filter_head = false;    
        }

        if(ip_head){
            ip_head = false;
        }else
            strcat(filter, " or ");

        if((g_filter_ipaddr[i]&0xffffff) ==0xffffff){
            ia.s_addr = htonl(g_filter_ipaddr[i]&0xff000000);
            sprintf(format, "(net %s mask 255.0.0.0)", inet_ntoa(ia));
            strcat(filter, format);
        }else if((g_filter_ipaddr[i]&0xffff) ==0xffff){
            ia.s_addr = htonl(g_filter_ipaddr[i]&0xffff0000);
            sprintf(format, "(net %s mask 255.255.0.0)", inet_ntoa(ia));
            strcat(filter, format);
        }else if((g_filter_ipaddr[i]&0xff) ==0xff){
            ia.s_addr = htonl(g_filter_ipaddr[i]&0xffffff00);
            sprintf(format, "(net %s mask 255.255.255.0)", inet_ntoa(ia));
            strcat(filter, format);
        }else{
            ia.s_addr = htonl(g_filter_ipaddr[i]);
            sprintf(format, "(host %s)", inet_ntoa(ia));
            strcat(filter, format);
        }
    }

    if(!ip_head) strcat(filter, ")");

    if(g_filter_protocol){
        if(!filter_head){
            strcat(filter, " and (");
        }else{
            filter_head = false;
            strcat(filter, "(");
        }

        if(g_filter_protocol & PROTOCOL_IP){
            if(!pro_head)
                strcat(filter, "or ip ");
            else{
                strcat(filter, "ip ");
                pro_head = false;
            }
        }
        
        if(g_filter_protocol & PROTOCOL_TCP){
            if(!pro_head)
                strcat(filter, "or tcp ");
            else{
                strcat(filter, "tcp ");
                pro_head = false;
            }
        }
        
        if(g_filter_protocol & PROTOCOL_UDP){
            if(!pro_head)
                strcat(filter, "or udp ");
            else{
                strcat(filter, "udp ");
                pro_head = false;
            }
        }
        
        if(g_filter_protocol & PROTOCOL_JOY){
            if(!pro_head)
                strcat(filter, "or ether proto 0x0905 ");
            else{
                strcat(filter, "ether proto 0x0905 ");
                pro_head = false;
            }
        }

        strcat(filter, ") ");
    }

    if(g_filter_protocol && g_filter_port){
        sprintf(format, "and port %d", g_filter_port);
        strcat(filter, format);
    }

    TRACE("FILTER STR : %s\n", filter);
    return filter;
}

UINT WorkThread(LPVOID pParam)
{
    //const char *adapter_name = (char*)pParam
    pcap_t      *hpcap;
    char error_info[PCAP_ERRBUF_SIZE];
    short adapter = (short)pParam;

    ASSERT(adapter < g_adapter_count);

    hpcap = pcap_open(g_adapter_names[adapter], 100, PCAP_OPENFLAG_PROMISCUOUS, 20, NULL, error_info);

    if(!hpcap){
        //fprintf(stderr,, 
        TRACE("Error in pcap open %s error: %s\n",g_adapter_names[adapter], error_info);
        g_open[adapter] = false;
        return 0;
    }else
        g_hpcap[adapter] = hpcap;
    ///* construct a filter */  
    struct bpf_program filter;  
    pcap_compile(hpcap, &filter, MakeFilter(), 1, 0);//""ether proto 0x0905""  
    pcap_setfilter(hpcap, &filter);

    while(g_open){
//        printf("dispathc...\n");
        pcap_dispatch(hpcap, 1, DispatchCallback, (u_char*)pParam); 
    }

    g_hpcap[adapter] = NULL;
    Sleep(100);
    pcap_close(hpcap);
    return 0;
}

int LoadAdapterNames()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    pcap_addr_t *a;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* Retrieve the adapters list */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
        return -1;
    }
        
    /* Scan the list printing every entry */
    for(d=alldevs;d && g_adapter_count < MAX_INTERFACE;d=d->next)
    {

        if(d->flags & PCAP_IF_LOOPBACK)     continue;

        //if(strstr(d->name, "eth") == NULL)  continue;
        //ifprint(d);
        strncpy_s(g_adapter_names[g_adapter_count], d->name, MAX_INTERFACE_NAME);
        TRACE("name %s des %s\n", d->name, d->description);

        for(a=d->addresses;a;a=a->next) {

            if(a->addr->sa_family == AF_INET)
            {
                if (a->addr)
                    g_adapter_addrs[g_adapter_count].s_addr = ((struct sockaddr_in *)(a->addr))->sin_addr.s_addr;

                //printf("\t%d Address: %s\n",g_adapter_count, inet_ntoa(((struct sockaddr_in *)(a->addr))->sin_addr));
                //ifprint(d);

                if (a->broadaddr)
                    g_adapter_mask[g_adapter_count].s_addr = ((struct sockaddr_in *)(a->netmask))->sin_addr.s_addr;

            }
        }

        ++g_adapter_count;
    }

    pcap_freealldevs(alldevs);

    return g_adapter_count;
}

int LoadMacAddr()
{
    IP_ADAPTER_INFO AdapterInfo[16];

    DWORD dwBufLen = sizeof(AdapterInfo);
    DWORD dwStatus = GetAdaptersInfo(AdapterInfo, &dwBufLen);

    ASSERT(dwStatus == ERROR_SUCCESS);

    PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;// Contains pointer to current adapter info

    int i=0;
    do{
        for(int j = 0; j < g_adapter_count; ++j){
            if(strstr(g_adapter_names[j]+20, pAdapterInfo->AdapterName) != NULL){
                memcpy(g_mac_addrs[j], pAdapterInfo->Address, 6);
                g_adapter_gateway[j].s_addr = inet_addr(pAdapterInfo->GatewayList.IpAddress.String);
                break;
                //PrintMACaddress(pAdapterInfo->AdapterName, pAdapterInfo->Address);// Print MAC address
            }
        }
        pAdapterInfo = pAdapterInfo->Next; // Progress through linked list
        ++i;
    }while(pAdapterInfo); // Terminate if last adapter

    return i;
}

int LoadDNS()
{
    FIXED_INFO fi[8];
    ULONG ulOutBufLen = sizeof(FIXED_INFO)*8;  
    int c = 0;
    DWORD rv;

    rv = ::GetNetworkParams(fi, &ulOutBufLen);
    // 获取本地电脑的网络参数  
    if(rv != ERROR_SUCCESS)  
    {  
        TRACE(" GetNetworkParams() failed \n");  
        return -1;  
    }
  
    //if(fi.DnsServerList != NULL){
    g_dns[0].s_addr = inet_addr(fi[0].DnsServerList.IpAddress.String);
    //}
    IP_ADDR_STRING *pIPAddr = fi[0].DnsServerList.Next;
    if(pIPAddr != NULL){
        g_dns[1].s_addr = inet_addr(pIPAddr->IpAddress.String);
        return 2;
    }else
        return 1;
}

CString GetAdapterName(char* adapter)
{
    if(NULL == strstr(adapter, "rpcap"))   return "";

    adapter += 8; //"rpcap://"

    CString AdapterName(adapter);

    HKEY hKey;

    CString strKeyName("SYSTEM\\ControlSet001\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\");
    strKeyName += AdapterName.Mid(12);
    strKeyName += "\\Connection";

    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        LPCTSTR(strKeyName),
        0,
        KEY_READ,
        &hKey) != ERROR_SUCCESS)
    {
        return "";
    }

    unsigned char szData[256];
    DWORD dwBufSize;
	
    CString temp;

    dwBufSize = sizeof(szData);
    if(RegQueryValueEx(hKey, TEXT("Name"), 0, 0, szData, &dwBufSize) == ERROR_SUCCESS)
    {	
       return CString(szData);
    }
    return "";
}

__declspec(dllexport) bool joyPcapInit()
{
    //deq_buffer.resize(512);
    LoadAdapterNames();
    LoadMacAddr();
    LoadDNS();
    //for(int i = 0; i < g_adapter_count; ++i){
    //    TRACE("%s  %02x-%02x-%02x-%02x-%02x-%02x\n", GetAdapterName(g_adapter_names[i]), g_mac_addrs[i][0], g_mac_addrs[i][1], g_mac_addrs[i][2], g_mac_addrs[i][3], g_mac_addrs[i][4], g_mac_addrs[i][5]);
    //    TRACE("%s  gateway %s\n", GetAdapterName(g_adapter_names[i]), inet_ntoa(g_adapter_gateway[i]));
    //}

    //TRACE("DNS1: %s \n", g_dns[0].s_addr !=0 ? inet_ntoa(g_dns[0]) : "");
    //TRACE("DNS2: %s \n", g_dns[1].s_addr !=0 ? inet_ntoa(g_dns[1]) : "");
    joyPcapClearFilter();
    return true;
}

__declspec(dllexport) bool joyPcapExit()
{
    for(short a = 0; a < g_adapter_count; ++a){
        joyPcapAdapterClose(a);
    }
    return true;
}

__declspec(dllexport) bool joyPcapAdapterList(short index, char* adapter)
{
    if(index >= g_adapter_count){
        if(adapter) strncpy_s(adapter, 1,"", 128);
        return false;
    }else{
        if(adapter) strcpy(adapter, GetAdapterName(g_adapter_names[index]));
        return true;
    }
}

__declspec(dllexport) bool joyPcapAddFilter(short type, long val)
{
    switch(type){
        case FILTER_PROTOCOL:
            g_filter_protocol |= LOWORD(val);
            break;
        case FILTER_PORT:
            g_filter_port = LOWORD(val);
            break;
        case FILTER_IPADDR:

            if(val == 0xffffffff)   return false;

            int i;
            for(i = 0; i < sizeof(g_filter_ipaddr); ++i)
                if(g_filter_ipaddr[i] == 0) break;

            if(i < sizeof(g_filter_ipaddr)) g_filter_ipaddr[i] = DWORD(val);
            break;
        case FILTER_MACADDR:
            //strncpy_s(s, (char*)val, sizeof(s));
            //s[2] = s[5] = s[8] = s[11] = s[14] = s[17] = '\0';
            //g_filter_macaddr[0] = atoc(s);
            //g_filter_macaddr[1] = atoc(s + 3);
            //g_filter_macaddr[2] = atoc(s + 6);
            //g_filter_macaddr[3] = atoc(s + 9);
            //g_filter_macaddr[4] = atoc(s +12);
            //g_filter_macaddr[5] = atoc(s +15);
            break;
        case FILTER_STRING:
            //strncpy_s(g_filter_expresion, (char*)(val), sizeof(g_filter_expresion));
            break;
        default:
            return false;
    }
    return true;
}

__declspec(dllexport) void joyPcapClearFilter()
{
    g_filter_protocol = 0;
    g_filter_port = 0;
    memset(g_filter_ipaddr, 0, 8*sizeof(int));
    //memset(g_filter_macaddr, 0, sizeof(g_filter_macaddr));
    //memset(g_filter_expresion, 0, sizeof(g_filter_expresion));
}

__declspec(dllexport) bool joyPcapAdapterOpen(short adapter)
{
//    static struct bpf_program filter;
    if(adapter >= g_adapter_count)    return false;

    g_open[adapter] = true;

	AfxBeginThread(WorkThread, (void*)adapter);
	Sleep(200);
    //g_open[adapter] maybe modified in thread if open failed!
    return g_open[adapter];
}

__declspec(dllexport) short joyPcapCapture(char* packet, short tmout, short* adapter)
{
    short sec = 0;
    while(deq_buffer.size() == 0){
        Sleep(1000);
        if(++sec > tmout){
            return 0;
        }
    }
    //lock
    cs.Lock();

    if(deq_buffer.size() == 0){
        cs.Unlock();
        return 0;
    }
    char *b = deq_buffer.front();
    deq_buffer.pop_front();

    cs.Unlock();

    *adapter = b[0];
    short len = MAKEWORD(b[1], b[2]);
    memcpy(packet, b+3, len);
    free(b);
    return len;
}

__declspec(dllexport) bool joyPcapSend(short adapter, char* packet, unsigned int len)
{
    unsigned int e;

    ASSERT(packet);

    if(adapter < 0 || adapter >= g_adapter_count){
        TRACE("adapter not found!");
        return false;
    }

    if(g_hpcap[adapter] == NULL){
        TRACE("adapter %s is not open!\n",GetAdapterName(g_adapter_names[adapter]));
        return false;
    }
    e =  pcap_sendpacket(g_hpcap[adapter], (const unsigned char*)packet, len);
    if(0 != e){
        TRACE("send error len %d, error no %d!\n", len, e);
        return false;
    }

    return true;
}

__declspec(dllexport) bool joyPcapAdapterClose(short adapter)
{
    if(g_open[adapter] == false)    return true;
    
    g_open[adapter] = false;
    Sleep(1000);

    bool all_close = true;
    for(int a = 0; a < g_adapter_count; ++a){
        if(g_open[adapter] == true){
            all_close = false;
            break;
        }
    }

    if(all_close){
        //lock
        cs.Lock();
        for(size_t i = 0; i < deq_buffer.size(); ++i)  free(deq_buffer[i]);
        deq_buffer.clear();
        cs.Unlock();
        //unlock
    }
    return true;
}
__declspec(dllexport) void joyPcapRefresh()
{
    g_adapter_count = 0;

    LoadAdapterNames();
    LoadMacAddr();
    LoadDNS();
}

__declspec(dllexport) unsigned char* joyPcapGetMac(short adapter_index)
{
    return adapter_index < g_adapter_count ? g_mac_addrs[adapter_index] : NULL;
}
__declspec(dllexport) unsigned int  joyPcapGetIp(short adapter_index)
{
    return adapter_index < g_adapter_count ? g_adapter_addrs[adapter_index].s_addr : 0;
}
__declspec(dllexport) unsigned int  joyPcapGetMask(short adapter_index)
{
    return adapter_index < g_adapter_count ? g_adapter_mask[adapter_index].s_addr : 0;
}

__declspec(dllexport) unsigned int  joyPcapGetGateway(short adapter_index)
{
    return adapter_index < g_adapter_count ? g_adapter_gateway[adapter_index].s_addr : 0;
}

__declspec(dllexport) unsigned int  joyPcapGetDNS(unsigned int *dns1, unsigned int *dns2)
{
    unsigned int rv = 0;
    
    if((*dns1 = g_dns[0].s_addr) != 0) ++rv;
    if((*dns2 = g_dns[1].s_addr) != 0) ++rv;

    return rv;
}