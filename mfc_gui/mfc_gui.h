
// mfc_gui.h : main header file for the mfc_gui application
//
#pragma once

#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"       // main symbols


// Cmfc_guiApp:
// See mfc_gui.cpp for the implementation of this class
//

class Cmfc_guiApp : public CWinAppEx
{
public:
	Cmfc_guiApp();


// Overrides
public:
	virtual BOOL InitInstance();

// Implementation

public:
	BOOL  m_bHiColorIcons;

	virtual void PreLoadState();
	virtual void LoadCustomState();
	virtual void SaveCustomState();

	afx_msg void OnAppAbout();
	DECLARE_MESSAGE_MAP()
};

extern Cmfc_guiApp theApp;
