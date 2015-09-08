#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>
#include <shellapi.h>
#include <stdio.h>

#define OPEN_KEY(parent, name, ptr) \
	RegCreateKeyExA(parent, name, 0, 0, 0, KEY_WRITE, 0, ptr, 0)
#define SET_VALUE(parent, name, value) \
	RegSetValueExA(parent, name, 0, REG_SZ, (const BYTE *)(value), (DWORD)strlen(value) + 1)

void win_install(void)
{
	char command_str[2048], argv0[2048];
	HKEY software, classes, mupdf;
	HKEY supported_types, shell, open, command;
	HKEY dotpdf, dotxps, dotcbz, dotepub;
	HKEY pdf_progids, xps_progids, cbz_progids, epub_progids;

	GetModuleFileNameA(NULL, argv0, sizeof argv0);
	_snprintf(command_str, sizeof command_str, "\"%s\" \"%%1\"", argv0);

	OPEN_KEY(HKEY_CURRENT_USER, "Software", &software);
	OPEN_KEY(software, "Classes", &classes);
	{
		OPEN_KEY(classes, "MuPDF", &mupdf);
		{
			OPEN_KEY(mupdf, "SupportedTypes", &supported_types);
			{
				SET_VALUE(supported_types, ".pdf", "");
				SET_VALUE(supported_types, ".xps", "");
				SET_VALUE(supported_types, ".cbz", "");
				SET_VALUE(supported_types, ".epub", "");
			}
			RegCloseKey(supported_types);
			OPEN_KEY(mupdf, "shell", &shell);
			OPEN_KEY(shell, "open", &open);
			OPEN_KEY(open, "command", &command);
			{
				SET_VALUE(open, "FriendlyAppName", "MuPDF");
				SET_VALUE(command, "", command_str);
			}
			RegCloseKey(command);
			RegCloseKey(open);
			RegCloseKey(shell);
		}
		RegCloseKey(mupdf);

		OPEN_KEY(classes, ".pdf", &dotpdf);
		OPEN_KEY(classes, ".xps", &dotxps);
		OPEN_KEY(classes, ".cbz", &dotcbz);
		OPEN_KEY(classes, ".epub", &dotepub);
		{
			OPEN_KEY(dotpdf, "OpenWithProgids", &pdf_progids);
			OPEN_KEY(dotxps, "OpenWithProgids", &xps_progids);
			OPEN_KEY(dotcbz, "OpenWithProgids", &cbz_progids);
			OPEN_KEY(dotepub, "OpenWithProgids", &epub_progids);
			{
				SET_VALUE(pdf_progids, "MuPDF", "");
				SET_VALUE(xps_progids, "MuPDF", "");
				SET_VALUE(cbz_progids, "MuPDF", "");
				SET_VALUE(epub_progids, "MuPDF", "");
			}
			RegCloseKey(pdf_progids);
			RegCloseKey(xps_progids);
			RegCloseKey(cbz_progids);
			RegCloseKey(epub_progids);
		}
		RegCloseKey(dotpdf);
		RegCloseKey(dotxps);
		RegCloseKey(dotcbz);
		RegCloseKey(dotepub);
	}
	RegCloseKey(classes);
	RegCloseKey(software);
}

int win_open_file(char *buf, int len)
{
	wchar_t wbuf[2048];
	OPENFILENAME ofn;
	int code;
	wbuf[0] = 0;
	memset(&ofn, 0, sizeof(OPENFILENAME));
	ofn.lStructSize = sizeof(OPENFILENAME);
	ofn.lpstrFile = wbuf;
	ofn.nMaxFile = 2048;
	ofn.lpstrTitle = L"MuPDF: Open PDF file";
	ofn.lpstrFilter = L"Documents (*.pdf;*.xps;*.cbz;*.epub;*.zip;*.png;*.jpeg;*.tiff)\0*.zip;*.cbz;*.xps;*.epub;*.pdf;*.jpe;*.jpg;*.jpeg;*.jfif;*.tif;*.tiff\0PDF Files (*.pdf)\0*.pdf\0XPS Files (*.xps)\0*.xps\0CBZ Files (*.cbz;*.zip)\0*.zip;*.cbz\0EPUB Files (*.epub)\0*.epub\0Image Files (*.png;*.jpeg;*.tiff)\0*.png;*.jpg;*.jpe;*.jpeg;*.jfif;*.tif;*.tiff\0All Files\0*\0\0";
	ofn.Flags = OFN_FILEMUSTEXIST|OFN_HIDEREADONLY;
	code = GetOpenFileNameW(&ofn);
	if (code)
		WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, buf, len, NULL, NULL);
	return code;
}

#endif
