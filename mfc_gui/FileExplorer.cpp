// FileExplorer.cpp
// Author: Ovidiu Cucu
// Homepage: http://www.codexpert.ro/
// Weblog: http://codexpert.ro/blog/

#include "StdAfx.h"
#include "FileExplorer.h"

void CFileExplorer::Create()
{
    ATLASSERT(NULL == m_pIExplorerBrowser); // create only once


     // create an IExplorerBrowser instance
    HRESULT hr = CoCreateInstance(CLSID_ExplorerBrowser, 
        NULL, CLSCTX_INPROC, IID_PPV_ARGS(&m_pIExplorerBrowser));

    ATLENSURE_SUCCEEDED(hr); // throw exception in case of failure
}

void CFileExplorer::SetOptions(EXPLORER_BROWSER_OPTIONS dwOptions /* = EBO_SHOWFRAMES | EBO_ALWAYSNAVIGATE*/)
{
    ATLASSERT(NULL != m_pIExplorerBrowser); // no valid IExplorerBrowser instance

    // set the current browser options
    HRESULT hr = m_pIExplorerBrowser->SetOptions(dwOptions);

    ATLENSURE_SUCCEEDED(hr); // throw exception in case of failure
}

void CFileExplorer::Initialize(HWND hWndParent, const CRect& rc, 
    UINT nViewMode /*= FVM_DETAILS*/, UINT nFlags /*= FWF_NONE*/)
{
    ATLASSERT(NULL != m_pIExplorerBrowser); // no valid IExplorerBrowser instance

     // prepare the browser to be navigated
    FOLDERSETTINGS folderSettings = {0};
    folderSettings.ViewMode = nViewMode;
    folderSettings.fFlags = nFlags;
    HRESULT hr = m_pIExplorerBrowser->Initialize(hWndParent, rc, &folderSettings);

    ATLENSURE_SUCCEEDED(hr); // throw exception in case of failure
}

void CFileExplorer::SetRect(const CRect& rc)
{
    ATLASSERT(NULL != m_pIExplorerBrowser); // no valid IExplorerBrowser instance

    // set the size and position of the browser window
    m_pIExplorerBrowser->SetRect(NULL, rc);
}

void CFileExplorer::BrowseToFolder(LPCTSTR pszPath)
{
    ATLASSERT(NULL != m_pIExplorerBrowser); // no valid IExplorerBrowser instance

    // get PIDL from path name
    CStringW strPath(pszPath);
    LPITEMIDLIST pidl = NULL;
    HRESULT hr = ::SHParseDisplayName(strPath, NULL, &pidl, 0, NULL);
    ATLENSURE_SUCCEEDED(hr); // throw exception in case of failure

    // browse to PIDL
    hr = m_pIExplorerBrowser->BrowseToIDList(pidl, SBSP_ABSOLUTE);
    if(FAILED(hr)) // in case of failure, free the list then throw an exception
    {
        ::ILFree(pidl);
        AtlThrow(hr);
    }
    ::ILFree(pidl);
}

void CFileExplorer::Destroy()
{
	m_pIExplorerBrowser->Destroy();
}

void CFileExplorer::GetSelectedFiles(CStringArray& arrSelection)
{
	CComPtr<IShellView> spSV;
	if (SUCCEEDED(m_pIExplorerBrowser->GetCurrentView(IID_PPV_ARGS(&spSV))))
	{
		CComPtr<IDataObject> spDataObject;
		if (SUCCEEDED(spSV->GetItemObject(SVGIO_SELECTION, IID_PPV_ARGS(&spDataObject))))
		{
			//Code adapted from http://www.codeproject.com/shell/shellextguide1.asp
			FORMATETC fmt = { CF_HDROP, NULL, DVASPECT_CONTENT,	-1, TYMED_HGLOBAL };
			STGMEDIUM stg;
			stg.tymed =  TYMED_HGLOBAL;

			if (SUCCEEDED(spDataObject->GetData(&fmt, &stg)))
			{
				HDROP hDrop = (HDROP) GlobalLock ( stg.hGlobal );

				UINT uNumFiles = DragQueryFile ( hDrop, 0xFFFFFFFF, NULL, 0 );
				HRESULT hr = S_OK;

				for(UINT i = 0; i < uNumFiles; i++)
				{
					TCHAR szPath[_MAX_PATH];
					szPath[0] = 0;
					DragQueryFile(hDrop, i, szPath, MAX_PATH);

					if (szPath[0] != 0)
						arrSelection.Add(szPath);	
				}

				GlobalUnlock ( stg.hGlobal );
				ReleaseStgMedium ( &stg );
			}
		}
	}
}