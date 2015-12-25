#if !defined(AFX_PCAPAGENT_H__6965200E_91AE_4B3D_AE8D_510A4E726A87__INCLUDED_)
#define AFX_PCAPAGENT_H__6965200E_91AE_4B3D_AE8D_510A4E726A87__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#define PCAPDLL_NAME "joyPcap.dll"

#define FILTER_PROTOCOL    1    //short:    0x0905
#define FILTER_PORT        2    //short:    8080
#define FILTER_IPADDR      3    //int:      addr:172.20.20.1 or mask 172.20.255.255
#define FILTER_MACADDR     4    //string:   "00:08:15:00:08:15"
#define FILTER_STRING      5    //string

#define PROTOCOL_IP        1
#define PROTOCOL_TCP       2
#define PROTOCOL_UDP       4

class CPcapAgent{
public:
    CPcapAgent();
    virtual ~CPcapAgent();

    bool Init();
    bool Start(int adapter);
    bool Stop();

    CString GetAdapterName(int index);  //0 based

    bool    AddFilter(short type, long val);
    void    ClearFilter();

    inline short GetCurrentAdapter(){  return m_CurrentAdapter;    }
private:
    HMODULE m_hPcapDll;
    short   m_CurrentAdapter;
};

#endif //AFX_PCAPAGENT_H__6965200E_91AE_4B3D_AE8D_510A4E726A87__INCLUDED_