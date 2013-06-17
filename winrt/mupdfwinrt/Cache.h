#pragma once

#include <mutex>
extern "C" {
	#include "mupdf/fitz.h"
}

#define MAX_DISPLAY_CACHE_SIZE 3

typedef struct cache_entry_s cache_entry_t;

struct cache_entry_s
{
	fz_display_list *dlist;
	cache_entry_t *next;
	cache_entry_t *prev;
	int index;
};

class Cache
{
private:
	int size;
	cache_entry_t *head;
	cache_entry_t *tail;
	std::mutex cache_lock;

public:
	Cache(void);
	~Cache(void);
	fz_display_list* UseEntry(int value, fz_context *mu_ctx);
	void AddEntry(int value, fz_display_list *dlist, fz_context *mu_ctx);
	void Empty(fz_context *mu_ctx);
};
