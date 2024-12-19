#pragma once

class CFileExplorer : public CObject
{
// Attributtes
private:
    CComPtr<IExplorerBrowser> m_pIExplorerBrowser;

// Operations
public:
    void Create();

    void SetOptions(EXPLORER_BROWSER_OPTIONS dwOptions = EBO_SHOWFRAMES | EBO_ALWAYSNAVIGATE);

    void Initialize(HWND hWndParent, const CRect& rc, 
                    UINT nViewMode = FVM_DETAILS, UINT nFlags = 0);

    void SetRect(const CRect& rc) throw();

    void BrowseToFolder(LPCTSTR pszPath);

	void Destroy();

public:
	void GetSelectedFiles(CStringArray& arrSelection);
	
    // NOTE: This class may be completed in a further implementation
};

