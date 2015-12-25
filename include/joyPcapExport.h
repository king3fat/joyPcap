#ifndef JOY_PCAP_EXPORT_H
#define JOY_PCAP_EXPORT_H  

#define MAX_INTERFACE      16

#define FILTER_PROTOCOL    1    //short:    0x0905
#define FILTER_PORT        2    //short:    8080
#define FILTER_IPADDR      3    //int:      addr:172.20.20.1 or mask 172.20.255.255
#define FILTER_MACADDR     4    //string:   "00:08:15:00:08:15"
#define FILTER_STRING      5    //string

#define PROTOCOL_IP        1
#define PROTOCOL_TCP       2
#define PROTOCOL_UDP       4
#define PROTOCOL_JOY       8

#ifdef __cplusplus
extern "C" {
#endif

__declspec(dllexport) bool           joyPcapInit();
__declspec(dllexport) bool           joyPcapExit();

__declspec(dllexport) bool           joyPcapAdapterList(short adapter, char* name);
__declspec(dllexport) bool           joyPcapAdapterOpen(short adapter);
__declspec(dllexport) bool           joyPcapAdapterClose(short adapter);

__declspec(dllexport) bool           joyPcapAddFilter(short type, long val);
__declspec(dllexport) void           joyPcapClearFilter();

__declspec(dllexport) short          joyPcapCapture(char* packet, short tmout, short* adapter);
__declspec(dllexport) bool           joyPcapSend(short adapter, char* packet, unsigned int len);

__declspec(dllexport) void           joyPcapRefresh();

__declspec(dllexport) unsigned char* joyPcapGetMac(short adapter_index);
__declspec(dllexport) unsigned int   joyPcapGetIp(short adapter_index);
__declspec(dllexport) unsigned int   joyPcapGetMask(short adapter_index);
__declspec(dllexport) unsigned int   joyPcapGetGateway(short adapter_index);
__declspec(dllexport) unsigned int   joyPcapGetDNS(unsigned int *dns1, unsigned int *dns2);
//__declspec(dllexport) unsigned int  ether_jw_setip(short adapter_index, unsigned int ip);
//__declspec(dllexport) unsigned int  ether_jw_setmask(short adapter_index, unsigned int mask);
//__declspec(dllexport) unsigned int  ether_jw_setgateway(short adapter_index, unsigned int gateway);
//

#ifdef __cplusplus
}
#endif

#endif  //JOY_PCAP_EXPORT_H
