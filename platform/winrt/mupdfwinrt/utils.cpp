#include "pch.h"
#include "utils.h"

/* Window string hurdles.... */
String^ char_to_String(char *char_in)
{
	size_t size = MultiByteToWideChar(CP_UTF8, 0, char_in, -1, NULL, 0);
	wchar_t *pw;
	pw = new wchar_t[size];
	if (!pw)
	{
		delete []pw;
		return nullptr;
	}
	MultiByteToWideChar(CP_UTF8, 0, char_in, -1, pw, size );
	String^ str_out = ref new String(pw);
	delete []pw;
	return str_out;
}

char* String_to_char(String^ text)
{
	const wchar_t *w = text->Data();
	int cb = WideCharToMultiByte(CP_UTF8, 0, text->Data(), -1, nullptr, 0, nullptr, nullptr);
	char* charout = new char[cb];
	WideCharToMultiByte(CP_UTF8, 0, text->Data() ,-1 ,charout ,cb ,nullptr, nullptr);
	return charout;
}
