#pragma once

typedef enum {
    LINK_GOTO = 0,
    LINK_URI,
    TEXTBOX,    /* Do double duty with this class */
    NOT_SET,
} link_t;