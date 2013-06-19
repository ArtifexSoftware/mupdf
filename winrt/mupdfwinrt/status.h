#pragma once

typedef enum {
	S_ISOK = 0,
	E_FAILURE = 1,
	E_OUTOFMEM = 2,
	E_NEEDPASSWORD
} status_t;

typedef enum {
	LINK_GOTO = 0,
	LINK_URI,
	TEXTBOX,	/* Do double duty with this class */
	NOT_SET,
} link_t;

#define SEARCH_FORWARD 1
#define SEARCH_BACKWARD -1
#define TEXT_NOT_FOUND -1
