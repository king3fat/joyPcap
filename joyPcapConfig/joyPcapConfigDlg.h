// joyPcapConfigDlg.h : header file
//

#pragma once
#include "afxwin.h"
#include "afxcmn.h"
#include "PcapAgent.h"

// CjoyPcapConfigDlg dialog
class CjoyPcapConfigDlg : public CDialog
{
// Construction
public:
	CjoyPcapConfigDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	enum { IDD = IDD_JOYPCAPCONFIG_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;
    CComboBox m_comboAdapter;
    CIPAddressCtrl m_IP1;
    CIPAddressCtrl m_IP2;
    CPcapAgent  m_agent;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
    afx_msg void OnBnClickedStart();
    afx_msg void OnBnClickedStop();
};
