// Copyright (C) 2025 Artifex Software, Inc.
//
// This file is part of MuPDF.
//
// MuPDF is free software: you can redistribute it and/or modify it under the
// terms of the GNU Affero General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// MuPDF is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
// details.
//
// You should have received a copy of the GNU Affero General Public License
// along with MuPDF. If not, see <https://www.gnu.org/licenses/agpl-3.0.en.html>
//
// Alternative licensing terms are available from the licensor.
// For commercial licensing, see <https://www.artifex.com/> or contact
// Artifex Software, Inc., 39 Mesa Street, Suite 108A, San Francisco,
// CA 94129, USA, for further information.

/*
 * mutool grep -- command line tool for searching in documents
 */

#include "mupdf/fitz.h"

static int mugrep_usage(void)
{
	fprintf(stderr,
		"usage: mugrep [options] pattern input.pdf [ input2.pdf ... ]\n"
		"\t-a\tignore accents (diacritics)\n"
		"\t-i\tignore case\n"
		"\t-p -\tpassword for encrypted PDF files\n"
		"\t-v\tverbose\n"
		"\t-G\tpattern is a regexp\n"
	);
	return EXIT_FAILURE;
}

/* Depth first traversal to next block that's not a struct. */
static fz_stext_block *
next_block(fz_stext_block *block, fz_stext_struct **str)
{
	while (1)
	{
next:
		/* Step forward. */
		block = block->next;
		if (block)
		{
			/* If we land on a struct, step down */
			while (block->type == FZ_STEXT_BLOCK_STRUCT)
			{
				/* Should never really happen, but if it does, just ignore it and step to the next */
				if (block->u.s.down == NULL)
					goto next;
				/* Step down */
				(*str) = block->u.s.down;
				block = (*str)->first_block;
				if (block == NULL)
					break;
			}
			if (block)
				return block;
		}

		/* Step up */
		if (*str == NULL)
			return NULL; /* No more ups to step! */
		block = (*str)->up;
		*str = (*str)->parent;
	}
}

/* Step the stext pos one char through the structure,
 * and the (unspun) haystack position in lockstep.
 * We cannot step through the spun haystack in this way,
 * as all pretence at a 1:1 relationship between the
 * stext and the spun_haystack has gone.
 * Return 1 if we hit EOD, 0 otherwise.
 */
static int
step_stext(fz_stext_position *spos)
{
	/* Step the char */
	spos->ch = spos->ch->next;
	if (spos->ch)
		return 0; /* Char! */

	/* Step the line */
	while (1)
	{
		spos->line = spos->line->next;
		if (spos->line == NULL)
			break;
		spos->ch = spos->line->first_char;
		if (spos->ch)
			return 1; /* Line */
	}
	/* Step the block */
	while (1)
	{
		spos->block = next_block(spos->block, &spos->struc);
		if (spos->block == NULL)
			return 3; /* End of stext */
		if (spos->block && spos->block->type == FZ_STEXT_BLOCK_TEXT)
		{
			spos->line = spos->block->u.t.first_line;
			while (spos->line)
			{
				spos->ch = spos->line->first_char;
				if (spos->ch)
				{
					return 2;
				}
				spos->line = spos->line->next;
			}
		}
	}
}

static void
feed_page(fz_context *ctx, fz_document *doc, fz_search *search, int page_num, fz_stext_options *options, int verbose)
{
	if (verbose)
		printf("FEEDING page %d\n", page_num);
	fz_stext_page *page = fz_new_stext_page_from_page_number(ctx, doc, page_num, options);
	fz_feed_search(ctx, search, page, page_num);
}

static void
search_test(fz_context *ctx, fz_search_options options, const char *needle, fz_document *doc, int verbose)
{
	fz_stext_options stext_options = { FZ_STEXT_DEHYPHENATE };
	int n = fz_count_pages(ctx, doc);
	fz_search *search = NULL;
	fz_search_result res;
	int i;
	fz_stext_position last_end;
	int line_found = 0;

	fz_var(search);

	fz_try(ctx)
	{
		search = fz_new_search(ctx);
		fz_search_set_options(ctx, search, options, needle);

		for (;;)
		{
			res = fz_search_forwards(ctx, search);
			if (res.reason == FZ_SEARCH_MATCH)
			{
				fz_search_result_details *details = res.u.match.result;
				fz_stext_position spos, end;

				if (verbose)
				{
					printf("Match: %d quads (starting on page %d)\n", details->num_quads, details->quads[0].seq);
				}

				spos = details->begin;
				end = details->end;
				/* Run backwards looking for the start of the line... */
				{
					fz_stext_line *line = spos.line;
					while (1)
					{
						float mid = (line->bbox.y0 + line->bbox.y1)/2;

						if (line->prev && line->prev->bbox.y0 < mid && line->prev->bbox.y1 > mid)
							line = line->prev;
						else
							break;
					}
					spos.line = line;
					spos.ch = line->first_char;
				}
				/* Run forwards looking for the end of the line... */
				{
					fz_stext_line *line = end.line;
					while (1)
					{
						float mid = (line->bbox.y0 + line->bbox.y1)/2;

						if (line->next && line->next->bbox.y0 < mid && line->next->bbox.y1 > mid)
							line = line->next;
						else
							break;
					}
					end.line = line;
					end.ch = line->last_char;
				}

				if (line_found && memcmp(&last_end, &end, sizeof(last_end)) == 0)
				{
					/* Another match in the same line. */
				}
				else
				{
					printf("Page %d: ", details->quads[0].seq+1);
					while (1)
					{
						char text[10];
						int len = fz_runetochar(text, spos.ch->c);
						for (i = 0; i < len; i++)
							printf("%c", text[i]);
						if (memcmp(&spos, &end, sizeof(spos)) == 0)
							break;
						i = step_stext(&spos);
						if (i == 1)
							printf("\\n");
						else if (i == 2)
							printf("\\n\\n");
						else if (i == 3)
						{
							/* WTF? */
							break;
						}
					}
					printf("\n");
				}
				line_found = 1;
				last_end = end;
			}
			else if (res.reason == FZ_SEARCH_MORE_INPUT)
			{
				if (res.u.more_input.seq_needed < 0 || res.u.more_input.seq_needed == n)
				{
					fz_feed_search(ctx, search, NULL, res.u.more_input.seq_needed);
				}
				else
				{
					feed_page(ctx, doc, search, res.u.more_input.seq_needed, &stext_options, verbose);
				}
			}
			else if (res.reason == FZ_SEARCH_COMPLETE)
			{
				break;
			}
		}
	}
	fz_always(ctx)
		fz_drop_search(ctx, search);
	fz_catch(ctx)
		fz_rethrow(ctx);
}

static int mugrep_run(fz_context *ctx, char *filename, fz_document *doc, char *pattern, fz_search_options options, int verbose)
{
	search_test(ctx, options, pattern, doc, verbose);
	return 0;
}

int mugrep_main(int argc, char **argv)
{
	fz_context *ctx;
	fz_document *doc = NULL;
	char *password = NULL; /* don't throw errors if encrypted */
	char *filename;
	char *pattern;
	int result = EXIT_FAILURE;
	int c;
	fz_search_options options = FZ_SEARCH_EXACT;
	int verbose = 0;

	ctx = fz_new_context(NULL, NULL, FZ_STORE_UNLIMITED);
	if (!ctx)
	{
		fprintf(stderr, "cannot initialise context\n");
		exit(1);
	}

	fz_register_document_handlers(ctx);

	while ((c = fz_getopt(argc, argv, "Gaip:v")) != -1)
	{
		switch (c)
		{
		case 'G': options |= FZ_SEARCH_REGEXP | FZ_SEARCH_KEEP_LINES | FZ_SEARCH_KEEP_PARAGRAPHS; break;
		case 'a': options |= FZ_SEARCH_IGNORE_DIACRITICS; break;
		case 'i': options |= FZ_SEARCH_IGNORE_CASE; break;
		case 'p': password = fz_optarg; break;
		case 'v': verbose = 1; break;
		default: return mugrep_usage();
		}
	}

	if (fz_optind == argc)
		return mugrep_usage();

	pattern = argv[fz_optind++];

	fz_var(doc);

	fz_try(ctx)
	{
		while (fz_optind < argc)
		{
			filename = argv[fz_optind++];

			doc = fz_open_document(ctx, filename);
			if (fz_needs_password(ctx, doc))
				if (!fz_authenticate_password(ctx, doc, password))
					fz_warn(ctx, "cannot authenticate password: %s", filename);

			if (mugrep_run(ctx, filename, doc, pattern, options, verbose))
				result = EXIT_SUCCESS;

			fz_drop_document(ctx, doc);
			doc = NULL;
		}
	}
	fz_always(ctx)
	{
		fz_drop_document(ctx, doc);
	}
	fz_catch(ctx)
	{
		fz_report_error(ctx);
		result = EXIT_FAILURE;
	}

	fz_drop_context(ctx);

	return result;
}
