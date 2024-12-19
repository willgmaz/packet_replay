
// ChildView.h : interface of the CChildView class
//


#pragma once

#include "FileExplorer.h"

// CChildView window

class CChildView : public CWnd
{
private:
	CFileExplorer m_fileExplorer;

// Construction
public:
	CChildView();

// Attributes
public:
	void OnUpdate();

// Operations
public:

// Overrides
	protected:
	virtual BOOL PreCreateWindow(CREATESTRUCT& cs);

// Implementation
public:
	virtual ~CChildView();

public:
	void GetSelectedFiles(CStringArray& arrSelection);


	// Generated message map functions
protected:
	afx_msg void OnPaint();
	DECLARE_MESSAGE_MAP()
	afx_msg int OnCreate(LPCREATESTRUCT lpCreateStruct);
	afx_msg void OnSize(UINT nType, int cx, int cy);
	afx_msg void OnDestroy();
};

