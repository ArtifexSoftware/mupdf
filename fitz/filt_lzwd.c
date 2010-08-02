#include "fitz.h"

/* TODO: error checking */

enum
{
	MINBITS = 9,
	MAXBITS = 12,
	NUMCODES = (1 << MAXBITS),
	LZW_CLEAR = 256,
	LZW_EOD = 257,
	LZW_FIRST = 258,
	MAXLENGTH = 4097
};

typedef struct lzw_code_s lzw_code;

struct lzw_code_s
{
	int prev;			/* prev code (in string) */
	unsigned short length;		/* string len, including this token */
	unsigned char value;		/* data value */
	unsigned char firstchar;	/* first token of string */
};

typedef struct fz_lzwd_s fz_lzwd;

struct fz_lzwd_s
{
	fz_stream *chain;
	int eod;

	int earlychange;

	unsigned int word;		/* bits loaded from data */
	int bidx;

	int codebits;			/* num bits/code */
	int code;			/* current code */
	int oldcode;			/* previously recognized code */
	int nextcode;			/* next free entry */
	lzw_code table[NUMCODES];

	unsigned char output[MAXLENGTH];
	int outlen;
	int remain;
};

static inline void eatbits(fz_lzwd *lzw, int nbits)
{
	lzw->word <<= nbits;
	lzw->bidx += nbits;
}

static inline int fillbits(fz_lzwd *lzw)
{
	while (lzw->bidx >= 8)
	{
		int c = fz_readbyte(lzw->chain);
		if (c == EOF)
			return EOF;
		lzw->bidx -= 8;
		lzw->word |= c << lzw->bidx;
	}
	return 0;
}

static inline void unstuff(fz_lzwd *lzw)
{
	int i = (32 - lzw->bidx) / 8;
	while (i--)
		fz_unreadbyte(lzw->chain);
}

static int
readlzwd(fz_stream *stm, unsigned char *buf, int len)
{
	fz_lzwd *lzw = stm->state;
	unsigned char *p = buf;
	unsigned char *s;

	while (lzw->remain > 0 && p < buf + len)
		*p++ = lzw->output[lzw->outlen - lzw->remain--];

	while (p < buf + len)
	{
		if (lzw->eod)
			return 0;

		if (fillbits(lzw))
		{
			if (lzw->bidx > 32 - lzw->codebits)
			{
				unstuff(lzw);
				lzw->eod = 1;
				return p - buf;
			}
		}

		lzw->code = lzw->word >> (32 - lzw->codebits);
		lzw->code &= (1 << lzw->codebits) - 1;
		eatbits(lzw, lzw->codebits);

		if (lzw->code == LZW_EOD)
		{
			unstuff(lzw);
			lzw->eod = 1;
			return p - buf;
		}

		if (lzw->code == LZW_CLEAR)
		{
			lzw->codebits = MINBITS;
			lzw->nextcode = LZW_FIRST;
			lzw->oldcode = -1;
			continue;
		}

		/* if stream starts without a clear code, oldcode is undefined... */
		if (lzw->oldcode == -1)
		{
			lzw->oldcode = lzw->code;
			goto output;
		}

		/* add new entry to the code table */
		lzw->table[lzw->nextcode].prev = lzw->oldcode;
		lzw->table[lzw->nextcode].firstchar = lzw->table[lzw->oldcode].firstchar;
		lzw->table[lzw->nextcode].length = lzw->table[lzw->oldcode].length + 1;
		if (lzw->code < lzw->nextcode)
			lzw->table[lzw->nextcode].value = lzw->table[lzw->code].firstchar;
		else if (lzw->code == lzw->nextcode)
			lzw->table[lzw->nextcode].value = lzw->table[lzw->nextcode].firstchar;
		else
			fz_warn("out of range code encountered in lzw decode");

		lzw->nextcode ++;

		if (lzw->nextcode > (1 << lzw->codebits) - lzw->earlychange - 1)
		{
			lzw->codebits ++;
			if (lzw->codebits > MAXBITS)
				lzw->codebits = MAXBITS;	/* FIXME */
		}

		lzw->oldcode = lzw->code;

output:

		/* code maps to a string, copy to output (in reverse...) */
		if (lzw->code > 255)
		{
			assert(lzw->table[lzw->code].length < MAXLENGTH);

			lzw->outlen = lzw->table[lzw->code].length;
			lzw->remain = lzw->outlen;
			s = lzw->output + lzw->remain;
			do {
				*(--s) = lzw->table[lzw->code].value;
				lzw->code = lzw->table[lzw->code].prev;
			} while (lzw->code >= 0 && s > lzw->output);
		}

		/* ... or just a single character */
		else
		{
			lzw->output[0] = lzw->code;
			lzw->outlen = 1;
			lzw->remain = 1;
		}

		/* copy to output */
		while (lzw->remain > 0 && p < buf + len)
			*p++ = lzw->output[lzw->outlen - lzw->remain--];
	}

	return p - buf;
}

static void
closelzwd(fz_stream *stm)
{
	fz_lzwd *lzw = stm->state;
	fz_close(lzw->chain);
	fz_free(lzw);
}

fz_stream *
fz_openlzwd(fz_stream *chain, fz_obj *params)
{
	fz_lzwd *lzw;
	fz_obj *obj;
	int i;

	lzw = fz_malloc(sizeof(fz_lzwd));
	lzw->chain = chain;
	lzw->eod = 0;
	lzw->earlychange = 1;

	obj = fz_dictgets(params, "EarlyChange");
	if (obj)
		lzw->earlychange = !!fz_toint(obj);

	lzw->bidx = 32;
	lzw->word = 0;

	for (i = 0; i < 256; i++)
	{
		lzw->table[i].value = i;
		lzw->table[i].firstchar = i;
		lzw->table[i].length = 1;
		lzw->table[i].prev = -1;
	}

	for (i = 256; i < NUMCODES; i++)
	{
		lzw->table[i].value = 0;
		lzw->table[i].firstchar = 0;
		lzw->table[i].length = 0;
		lzw->table[i].prev = -1;
	}

	lzw->codebits = MINBITS;
	lzw->code = -1;
	lzw->nextcode = LZW_FIRST;
	lzw->oldcode = -1;
	lzw->remain = 0;
	lzw->outlen = 0;

	return fz_newstream(lzw, readlzwd, closelzwd);
}
