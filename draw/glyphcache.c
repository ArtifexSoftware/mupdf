#include "fitz.h"

typedef struct fz_glyphkey_s fz_glyphkey;

struct fz_glyphcache_s
{
	fz_hashtable *hash;
};

struct fz_glyphkey_s
{
	void *font;
	int a, b;
	int c, d;
	unsigned short cid;
	unsigned char e, f;
};

fz_glyphcache *
fz_newglyphcache(void)
{
	fz_glyphcache *arena;
	
	arena = fz_malloc(sizeof(fz_glyphcache));
	arena->hash = fz_newhash(509, sizeof(fz_glyphkey));

	return arena;
}

void
fz_evictglyphcache(fz_glyphcache *arena)
{
	fz_pixmap *pixmap;
	int i;

	for (i = 0; i < fz_hashlen(arena->hash); i++)
	{
		pixmap = fz_hashgetval(arena->hash, i);
		if (pixmap)
			fz_droppixmap(pixmap);
	}

	fz_emptyhash(arena->hash);
}

void
fz_freeglyphcache(fz_glyphcache *arena)
{
	fz_evictglyphcache(arena);
	fz_drophash(arena->hash);
	fz_free(arena);
}

fz_pixmap *
fz_renderglyph(fz_glyphcache *arena, fz_font *font, int cid, fz_matrix ctm)
{
	fz_glyphkey key;
	fz_pixmap *val;

	key.font = font;
	key.cid = cid;
	key.a = ctm.a * 65536;
	key.b = ctm.b * 65536;
	key.c = ctm.c * 65536;
	key.d = ctm.d * 65536;
	key.e = (ctm.e - floor(ctm.e)) * 256;
	key.f = (ctm.f - floor(ctm.f)) * 256;

	val = fz_hashfind(arena->hash, &key);
	if (val)
		return fz_keeppixmap(val);

	ctm.e = floor(ctm.e) + key.e / 256.0;
	ctm.f = floor(ctm.f) + key.f / 256.0;

	if (font->ftface)
	{
		val = fz_renderftglyph(font, cid, ctm);
	}
	else if (font->t3procs)
	{
		val = fz_rendert3glyph(font, cid, ctm);
	}
	else
	{
		fz_warn("assert: uninitialized font structure");
		return NULL;
	}

	if (val)
	{
		fz_hashinsert(arena->hash, &key, val);
		return fz_keeppixmap(val);
	}
	
	return NULL;
}
