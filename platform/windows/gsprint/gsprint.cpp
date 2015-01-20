// gsprint.cpp : Defines the exported functions for the DLL application.
//
#include "gsprint.h"
#include "stdlib.h"

#define FAIL -1

/* Code to handle the special device properties window as well as make sure
 * that the values are maintained when we leave */
SYMBOL_DECLSPEC int __stdcall ShowPropertiesDialog(void *hptr, void *printername, bool show_win)
{
	HWND hWnd = (HWND)hptr;
	HANDLE hPrinter = NULL;
	LPDEVMODE pDevMode;
	DWORD dwNeeded, dwRet;
	wchar_t *output = NULL;

	int lenA = lstrlenA((char*)printername);
	int lenW = ::MultiByteToWideChar(CP_ACP, 0, (char*)printername, lenA, NULL, 0);
	if (lenW > 0)
	{
		output = new wchar_t[lenW + 1];
		if (output == NULL)
			return -1;
		::MultiByteToWideChar(CP_ACP, 0, (char*)printername, lenA, output, lenW);
		output[lenW] = 0;
	}
	else
		return FAIL;

	if (!OpenPrinter(output, &hPrinter, NULL))
	{
		free(output);
		return FAIL;
	}

	/* First get the size needed */
	dwNeeded = DocumentProperties(hWnd, hPrinter, output, NULL, NULL, 0);
	pDevMode = (LPDEVMODE)malloc(dwNeeded);
	if (pDevMode == NULL)
	{
		free(output);
		ClosePrinter(hPrinter);
		return FAIL;
	}

	/* Now actually get the DEVMODE data. DM_IN_PROMPT brings up the window.
	 * DM_OUT_BUFFER ensures that we get the values that have been set */
	DWORD fMode = DM_OUT_BUFFER;
	if (show_win)
		fMode = fMode | DM_IN_PROMPT;
	
	dwRet = DocumentProperties(hWnd, hPrinter, output, pDevMode, NULL, fMode);
	if (dwRet != IDOK)
	{
		free(output);
		ClosePrinter(hPrinter);
		free(pDevMode);
		return FAIL;
	}

	/* This is the secret to ensure that the DEVMODE settings are saved.  Fun
	 * finding this bit of information in the MS literature */
	PRINTER_INFO_9 new_info;
	new_info.pDevMode = pDevMode;
	SetPrinter(hPrinter, 9, (LPBYTE)&new_info, 0);

	/* Clean up */
	free(pDevMode);
	free(output);
	ClosePrinter(hPrinter);
	return 0;
}
