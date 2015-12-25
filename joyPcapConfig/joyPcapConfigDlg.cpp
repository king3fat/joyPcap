// joyPcapConfigDlg.cpp : implementation file
//

#include "stdafx.h"
#include "joyPcapConfig.h"
#include "joyPcapConfigDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CjoyPcapConfigDlg dialog




CjoyPcapConfigDlg::CjoyPcapConfigDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CjoyPcapConfigDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CjoyPcapConfigDlg::DoDataExchange(CDataExchange* pDX)
{
    CDialog::DoDataExchange(pDX);
    DDX_Control(pDX, IDC_COMBO_ADAPTER, m_comboAdapter);
    DDX_Control(pDX, IDC_IPADDRESS1, m_IP1);
    DDX_Control(pDX, IDC_IPADDRESS2, m_IP2);
}

BEGIN_MESSAGE_MAP(CjoyPcapConfigDlg, CDialog)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
    ON_BN_CLICKED(ID_START, &CjoyPcapConfigDlg::OnBnClickedStart)
    ON_BN_CLICKED(ID_STOP, &CjoyPcapConfigDlg::OnBnClickedStop)
END_MESSAGE_MAP()


// CjoyPcapConfigDlg message handlers

BOOL CjoyPcapConfigDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

    m_agent.Init();
	// TODO: Add extra initialization here
    short i = 0;
    do{
        CString a = m_agent.GetAdapterName(i);
        if(a.GetLength() > 0)
            m_comboAdapter.AddString(a);
        else
            break;
    }while(++i);

    if(m_comboAdapter.GetCount() > 0){
        m_comboAdapter.SetCurSel(0);
        GetDlgItem(ID_START)->EnableWindow();
    }else
        GetDlgItem(ID_START)->EnableWindow(false);

    GetDlgItem(ID_STOP)->EnableWindow(false);

    m_IP1.SetAddress(0);
    m_IP2.SetAddress(0);

    ((CButton *)GetDlgItem(IDC_RADIO_TCP))->SetCheck(TRUE);

    GetDlgItem(IDC_EDIT_PORT)->SetWindowTextA("0");
    return TRUE;  // return TRUE  unless you set the focus to a control
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CjoyPcapConfigDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CjoyPcapConfigDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CjoyPcapConfigDlg::OnBnClickedStart()
{
    DWORD  mask1, mask2;

    m_agent.ClearFilter();

    m_IP1.GetAddress(mask1);
    m_IP2.GetAddress(mask2);

    if(mask1)   m_agent.AddFilter(FILTER_IPADDR, mask1);
    if(mask2)   m_agent.AddFilter(FILTER_IPADDR, mask2);

    if(((CButton *)GetDlgItem(IDC_RADIO_TCP))->GetCheck())
        m_agent.AddFilter(FILTER_PROTOCOL, PROTOCOL_TCP);
    else
        m_agent.AddFilter(FILTER_PROTOCOL, PROTOCOL_UDP);

    CString strPort;
    GetDlgItem(IDC_EDIT_PORT)->GetWindowTextA(strPort);

    int port = atoi(LPCTSTR(strPort));
    if(port < 0 || port > 65535){
        ::AfxMessageBox("请输入0 ~ 65535之间数字！");
        return;
    }

    m_agent.AddFilter(FILTER_PORT, port);

    if(m_agent.Start(m_comboAdapter.GetCurSel())){
        GetDlgItem(ID_START)->EnableWindow(false);
        GetDlgItem(ID_STOP)->EnableWindow(true);

        m_comboAdapter.EnableWindow(false);
        m_IP1.EnableWindow(false);
        m_IP2.EnableWindow(false);
        GetDlgItem(IDC_EDIT_PORT)->EnableWindow(false);
        GetDlgItem(IDC_RADIO_TCP)->EnableWindow(false);
        GetDlgItem(IDC_RADIO_UDP)->EnableWindow(false);
    }
}

void CjoyPcapConfigDlg::OnBnClickedStop()
{

    if(m_agent.Stop()){

        m_agent.ClearFilter();

        GetDlgItem(ID_START)->EnableWindow(true);
        GetDlgItem(ID_STOP)->EnableWindow(false);

        m_comboAdapter.EnableWindow(true);
        m_IP1.EnableWindow(true);
        m_IP2.EnableWindow(true);
        GetDlgItem(IDC_EDIT_PORT)->EnableWindow(true);
        GetDlgItem(IDC_RADIO_TCP)->EnableWindow(true);
        GetDlgItem(IDC_RADIO_UDP)->EnableWindow(true);
    }
}
