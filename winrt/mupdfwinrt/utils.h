#pragma once

#include "Windows.h"
using namespace Platform;

typedef enum {
	LINK_GOTO = 0,
	LINK_URI,
	TEXTBOX,	/* Do double duty with this class */
	NOT_SET,
} link_t;

String^ char_to_String(char *char_in);
char* String_to_char(String^ text);
