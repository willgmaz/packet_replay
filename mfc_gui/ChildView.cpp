
// ChildView.cpp : implementation of the CChildView class
//

#include "stdafx.h"
#include "mfc_gui.h"
#include "ChildView.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CChildView

CChildView::CChildView()
{
}

CChildView::~CChildView()
{
}


BEGIN_MESSAGE_MAP(CChildView, CWnd)
	ON_WM_PAINT()
	ON_WM_CREATE()
	ON_WM_SIZE()
	ON_WM_DESTROY()
END_MESSAGE_MAP()



// CChildView message handlers

BOOL CChildView::PreCreateWindow(CREATESTRUCT& cs) 
{
	if (!CWnd::PreCreateWindow(cs))
		return FALSE;

	cs.dwExStyle |= WS_EX_CLIENTEDGE;
	cs.style &= ~WS_BORDER;
	cs.lpszClass = AfxRegisterWndClass(CS_HREDRAW|CS_VREDRAW|CS_DBLCLKS, 
		::LoadCursor(NULL, IDC_ARROW), reinterpret_cast<HBRUSH>(COLOR_WINDOW+1), NULL);

	return TRUE;
}

void CChildView::OnPaint() 
{
	CPaintDC dc(this); // device context for painting
	
	// TODO: Add your message handler code here
	
	// Do not call CWnd::OnPaint() for painting messages
}

int CChildView::OnCreate(LPCREATESTRUCT lpCreateStruct)
{
	if(CWnd::OnCreate(lpCreateStruct) == -1)
		return -1;

	try
	{
		// create IExplorerBrowser instance
		m_fileExplorer.Create();
		// set default browser options EBO_SHOWFRAMES | EBO_ALWAYSNAVIGATE
		m_fileExplorer.SetOptions();
		// prepares the browser to be navigated
		// partent window is this window, default view mode is FVM_DETAILS, 
		// default folder flag is FWF_NONE
		m_fileExplorer.Initialize(m_hWnd, CRect(0, 0, 0, 0));
		// NOTE: a further implementation can change the default values

		OnUpdate();
	}
	catch(COleException* e)
	{
		e->ReportError(); // show what's going wrong
		e->Delete();
		return -1;
	}
	return 0;
}


void CChildView::OnSize(UINT nType, int cx, int cy)
{
	CWnd::OnSize(nType, cx, cy);
	// resize the browser to fit this window's clent area
	m_fileExplorer.SetRect(CRect(0, 0, cx, cy));
}

void CChildView::OnUpdate()
{
	TCHAR pszDesktopFolder[MAX_PATH] = {0};
	::SHGetFolderPath(NULL, CSIDL_DESKTOP, NULL, SHGFP_TYPE_CURRENT, pszDesktopFolder);
	m_fileExplorer.BrowseToFolder(pszDesktopFolder);

	// NOTE: just for demo purpose, this browses using the desktop as root folder.
	// In a complete implementation you may change this, 
	// by using any other root path.
}

void CChildView::OnDestroy()
{
	m_fileExplorer.Destroy();
	CWnd::OnDestroy();
}

void CChildView::GetSelectedFiles(CStringArray& arrSelection)
{
	return m_fileExplorer.GetSelectedFiles(arrSelection);
}

